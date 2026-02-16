# QEMU Live Snapshotting with userfaultfd: A Technical Deep Dive

This document describes how QEMU implements live VM snapshotting using the Linux
`userfaultfd` (uffd) subsystem. It is written for VMM and microVM developers who
want to implement a similar capability. All code references are to the QEMU
source tree at the time of writing.

---

## Table of Contents

1. [Overview and Design Goals](#1-overview-and-design-goals)
2. [userfaultfd Kernel Primer](#2-userfaultfd-kernel-primer)
3. [QEMU's Two uffd-Based Mechanisms](#3-qemus-two-uffd-based-mechanisms)
4. [Background Snapshots (UFFD-WP)](#4-background-snapshots-uffd-wp)
5. [Postcopy Live Migration (UFFD Missing-Page)](#5-postcopy-live-migration-uffd-missing-page)
6. [The userfaultfd Abstraction Layer](#6-the-userfaultfd-abstraction-layer)
7. [Dirty Tracking Without Hardware Dirty Logging](#7-dirty-tracking-without-hardware-dirty-logging)
8. [Page Fault Resolution and Page Placement](#8-page-fault-resolution-and-page-placement)
9. [Blocktime Instrumentation](#9-blocktime-instrumentation)
10. [Design Tradeoffs and Pitfalls](#10-design-tradeoffs-and-pitfalls)
11. [Kernel Version Requirements](#11-kernel-version-requirements)
12. [Key Source Files](#12-key-source-files)

---

## 1. Overview and Design Goals

A live snapshot captures the complete state of a running VM — CPU registers,
device state, and the full contents of RAM — while the guest continues to
execute. The naive approach (pause the VM, serialize everything, resume) has
downtime proportional to RAM size. QEMU solves this with two distinct
uffd-based mechanisms:

**Background snapshots** (source-side, write-protect mode): The VM keeps running
while RAM is streamed out. uffd write-protection traps guest writes to pages
that haven't been saved yet, ensuring each page is captured exactly once in its
state at the instant the snapshot began.

**Postcopy migration** (destination-side, missing-page mode): The VM starts
executing at the destination before all RAM has arrived. Accesses to
not-yet-transferred pages trigger uffd missing-page faults, which are resolved
by fetching the page from the source on demand.

Both mechanisms share a common uffd abstraction layer (`util/userfaultfd.c`) and
integrate with QEMU's existing migration/savevm infrastructure.

---

## 2. userfaultfd Kernel Primer

`userfaultfd` is a Linux kernel mechanism that delegates page fault handling to
userspace. Instead of the kernel resolving a fault (e.g. by allocating a zero
page), it suspends the faulting thread and delivers a message to a userspace file
descriptor. Userspace then resolves the fault via ioctl and the faulting thread
resumes transparently.

### Key ioctl operations

| ioctl | Purpose |
|---|---|
| `UFFDIO_API` | Handshake: negotiate API version and features |
| `UFFDIO_REGISTER` | Register a virtual address range for fault tracking |
| `UFFDIO_UNREGISTER` | Remove tracking for an address range |
| `UFFDIO_COPY` | Resolve a missing-page fault by copying data into the faulted page |
| `UFFDIO_ZEROPAGE` | Resolve a missing-page fault with a zero-filled page |
| `UFFDIO_WRITEPROTECT` | Enable/disable write-protection on a range |
| `UFFDIO_WAKE` | Wake threads blocked on a fault (used after batched DONTWAKE operations) |

### Registration modes

- **`UFFDIO_REGISTER_MODE_MISSING`**: Traps accesses to pages that have no
  backing physical page (the page table entry is empty). Used by postcopy.
- **`UFFDIO_REGISTER_MODE_WP`**: Traps writes to pages that have been
  write-protected via `UFFDIO_WRITEPROTECT`. Used by background snapshots.

### Fault delivery

Faults are delivered as `struct uffd_msg` by `read()`ing the uffd file
descriptor. The message contains:

```c
struct uffd_msg {
    __u8  event;                    // UFFD_EVENT_PAGEFAULT
    struct {
        __u64 flags;                // UFFD_PAGEFAULT_FLAG_WRITE, _WP, etc.
        __u64 address;              // Faulted host virtual address
        union { __u32 ptid; };      // Thread ID (if UFFD_FEATURE_THREAD_ID)
    } arg.pagefault;
};
```

The uffd fd can be opened non-blocking (`O_NONBLOCK`) and multiplexed with
`poll()`.

### Opening the uffd fd

QEMU prefers `/dev/userfaultfd` (available on newer kernels) because it has
better permission controls and doesn't require `CAP_SYS_PTRACE`. It falls back
to the `__NR_userfaultfd` syscall if the device isn't available
(`util/userfaultfd.c:28`).

---

## 3. QEMU's Two uffd-Based Mechanisms

| Property | Background Snapshot (UFFD-WP) | Postcopy Migration (UFFD Missing) |
|---|---|---|
| **Side** | Source (snapshot origin) | Destination (restore target) |
| **uffd mode** | `UFFDIO_REGISTER_MODE_WP` | `UFFDIO_REGISTER_MODE_MISSING` |
| **Kernel feature** | `UFFD_FEATURE_PAGEFAULT_FLAG_WP` (Linux 5.7+) | `UFFD_FEATURE_MISSING_*` |
| **What triggers faults** | Guest writes to not-yet-saved pages | Any access to not-yet-received pages |
| **Who resolves faults** | Migration thread saves the page, then unprotects | Fault thread requests page from source, source sends it, uffd `COPY` resolves |
| **Threading** | Single migration thread polls uffd fd | Dedicated fault thread + optional preempt thread |
| **Dirty tracking** | uffd write faults *are* the dirty tracking | Not applicable (destination side) |

Both can coexist in the same QEMU binary. They are mutually exclusive at
runtime: `migrate_background_snapshot()` and `migrate_postcopy()` cannot both be
enabled for the same migration.

---

## 4. Background Snapshots (UFFD-WP)

This is the core "live snapshot" mechanism. It is implemented across
`migration/migration.c` (thread orchestration) and `migration/ram.c` (page
iteration and protection management).

### 4.1 High-Level Flow

```
                              ┌─────────────────────┐
                              │  bg_migration_thread │
                              └──────────┬──────────┘
                                         │
    Phase 1: SETUP                       │
    ──────────────────────               │
    ├─ Populate all RAM pages            │  ram_write_tracking_prepare()
    │  (touch every page so PTEs exist)  │
    ├─ Write migration stream header     │  qemu_savevm_state_header()
    ├─ Initialize RAM save handlers      │  qemu_savevm_state_setup()
    │                                    │
    Phase 2: FREEZE DEVICE STATE         │
    ──────────────────────               │
    ├─ Stop VM (brief pause)             │  migration_stop_vm()
    ├─ Serialize all non-RAM state       │  qemu_savevm_state_complete_precopy_non_iterable()
    │  into temporary buffer (s->bioc)   │
    ├─ Enable UFFD-WP on all RAM         │  ram_write_tracking_start()
    ├─ Resume VM via BH                  │  bg_migration_vm_start_bh()
    │                                    │
    Phase 3: STREAM RAM (VM running)     │
    ──────────────────────               │
    ├─ Loop:                             │
    │   ├─ Iterate dirty bitmap          │  qemu_savevm_state_iterate()
    │   │   ├─ poll_fault_page()         │  ← prioritize faulted pages
    │   │   ├─ pss_find_next_dirty()     │  ← then scan bitmap linearly
    │   │   ├─ Save page to stream       │
    │   │   └─ Unprotect saved range     │  ram_save_release_protection()
    │   └─ Repeat until all pages saved  │
    │                                    │
    Phase 4: COMPLETION                  │
    ──────────────────────               │
    ├─ Append buffered device state      │  qemu_put_buffer(s->bioc)
    ├─ Stop UFFD-WP tracking             │  ram_write_tracking_stop()
    └─ Cleanup                           │  bg_migration_iteration_finish()
```

### 4.2 Why the Device State Goes First (Temporally) but Last (In Stream)

This is the key insight of the design. The comment at
`migration/migration.c:3628` explains:

> We want to save vmstate for the moment when migration has been initiated but
> also we want to save RAM content while VM is running. The RAM content should
> appear first in the vmstate. So, we first stash the non-RAM part of the
> vmstate to the temporary buffer, then write RAM part of the vmstate to the
> migration stream with vCPUs running and, finally, write stashed non-RAM part
> of the vmstate from the buffer to the migration stream.

The device state is captured during a brief VM pause. The RAM, saved afterwards
with the VM running, reflects its state at the moment write-protection was
enabled — which is the same instant the device state was frozen. Write-protection
guarantees that any page saved to the stream is in its state from that frozen
moment: if the guest writes a page before the migration thread has saved it, the
write fault blocks the guest, the migration thread prioritizes that page, saves
it, unprotects it, and the guest's write proceeds.

This means the snapshot reflects VM state at a single point in time (the pause),
unlike dirty-log-based migration where the snapshot reflects the state at
completion.

### 4.3 Page Population: Why It Matters

Before enabling write-protection, QEMU must ensure every RAM page has a page
table entry (PTE). The `UFFDIO_WRITEPROTECT` ioctl silently skips pages with
`pte_none()` entries — if a page was never touched by the guest, there's no PTE
to write-protect, and a subsequent first write would succeed without generating a
uffd event.

`ram_write_tracking_prepare()` (`migration/ram.c:1649`) handles this by reading
one byte from every page:

```c
for (; offset < end; offset += block->page_size) {
    char tmp = *((char *)block->host + offset);
    asm volatile("" : "+r" (tmp));  // Prevent optimization
}
```

This forces the kernel to populate page tables. The `asm volatile` prevents the
compiler from optimizing away the read.

For regions managed by a `RamDiscardManager` (e.g. virtio-mem), only populated
sub-ranges are touched.

### 4.4 Write-Protection Setup

`ram_write_tracking_start()` (`migration/ram.c:1711`):

1. Creates a uffd fd with `UFFD_FEATURE_PAGEFAULT_FLAG_WP`
2. Iterates all non-readonly, non-ROM RAMBlocks
3. For each block:
   - `uffd_register_memory()` with `UFFDIO_REGISTER_MODE_WP`
   - `uffd_change_protection()` to write-protect the entire range
   - Sets `block->flags |= RAM_UF_WRITEPROTECT`
   - Takes a reference on the MemoryRegion to prevent it being freed

If any step fails, it unwinds: unregisters already-registered blocks, clears
flags, and closes the uffd fd.

### 4.5 Handling Write Faults During Iteration

The migration thread doesn't use a separate fault handler thread. Instead, it
polls the uffd fd inline during the page iteration loop.

In `get_queued_page()` (`migration/ram.c:1850`), after checking for explicit
postcopy page requests (which don't apply here), the code calls:

```c
block = poll_fault_page(rs, &offset);
```

`poll_fault_page()` (`migration/ram.c:1470`) does a non-blocking read on
`rs->uffdio_fd`. If a write fault is pending:

1. Extracts the faulting HVA from `uffd_msg.arg.pagefault.address`
2. Translates it to a RAMBlock + offset via `qemu_ram_block_from_host()`
3. Returns the block, causing the migration thread to prioritize saving that
   page

The faulting vCPU thread remains blocked in the kernel until the page is saved
and unprotected.

### 4.6 Releasing Write-Protection After Save

After saving a contiguous range of pages within a host page,
`ram_save_release_protection()` (`migration/ram.c:1502`):

1. Flushes the migration stream (`qemu_fflush`) — the data must be committed
   before unprotecting, otherwise a guest write could race with the stream write
2. Calls `uffd_change_protection(fd, addr, len, false, false)` — the
   `UFFDIO_WRITEPROTECT` ioctl with `mode=0` removes write-protection
3. Any vCPU blocked on a write fault to that range is automatically woken

### 4.7 No Dirty Logging

Background snapshots deliberately skip hardware dirty logging. The bitmap is
initialized to all-1s (every page marked dirty) and never synced from KVM/TCG.
Instead, the bitmap serves as a "not yet saved" tracker: bits are cleared as
pages are saved.

From `ram_init_bitmaps()` (`migration/ram.c:2874`):

```c
if (!migrate_background_snapshot()) {
    memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION, errp);
    migration_bitmap_sync_precopy(false);
}
```

And similarly in cleanup:

```c
if (!migrate_background_snapshot()) {
    memory_global_dirty_log_stop(GLOBAL_DIRTY_MIGRATION);
}
```

This is a significant simplification: no KVM `KVM_GET_DIRTY_LOG` ioctls, no
bitmap syncing, no deferred clearing. The uffd write faults provide an exact,
per-page "this page was written" signal at exactly the right granularity.

### 4.8 Completion and Stream Layout

When all pages have been saved (`qemu_savevm_state_iterate()` returns > 0),
`bg_migration_completion()` (`migration/migration.c:2841`) appends the buffered
device state:

```c
qemu_put_buffer(s->to_dst_file, s->bioc->data, s->bioc->usage);
qemu_fflush(s->to_dst_file);
```

The final stream layout is:

```
┌──────────────────────┐
│ Migration header     │  magic, version, configuration
├──────────────────────┤
│ RAM_SAVE_FLAG_EOS    │  end of setup
├──────────────────────┤
│ RAM pages (iterated) │  bulk of the stream, written with VM running
│  ...                 │
│ RAM_SAVE_FLAG_EOS    │  end of RAM
├──────────────────────┤
│ Device state         │  from bioc buffer, captured during brief pause
│ QEMU_VM_EOF          │
└──────────────────────┘
```

### 4.9 VM Resume via BH

After enabling write-protection, the VM is resumed from a bottom-half handler
rather than directly:

```c
migration_bh_schedule(bg_migration_vm_start_bh, s);
```

The comment at `migration/migration.c:3697` explains why:

> Start VM from BH handler to avoid write-fault lock here. UFFD-WP protection
> for the whole RAM is already enabled so calling VM state change notifiers from
> vm_start() would initiate writes to virtio VQs memory which is in
> write-protected region.

If `vm_start()` were called directly while holding the BQL, and a state-change
notifier wrote to write-protected memory, the write fault would deadlock — the
migration thread is the one that resolves faults, but it's blocked waiting for
`vm_start()` to return.

---

## 5. Postcopy Live Migration (UFFD Missing-Page)

Postcopy uses uffd in `UFFDIO_REGISTER_MODE_MISSING` mode on the
**destination** side. The destination VM begins executing before all RAM has
arrived; accesses to not-yet-received pages trap via uffd and trigger on-demand
page fetching from the source.

### 5.1 State Machine

```
POSTCOPY_INCOMING_NONE
  → ADVISE      Host capability check, initial RAM mapping
  → DISCARD     Huge pages disabled (MADV_NOHUGEPAGE), discardable regions marked
  → LISTENING   Fault thread started, RAM registered with uffd
  → RUNNING     Destination vCPUs started, faults trigger page requests
  → END         Cleanup, uffd unregistered
```

### 5.2 Destination Setup

`postcopy_ram_incoming_setup()` (`migration/postcopy-ram.c:1520`):

1. Opens uffd fd: `uffd_open(O_CLOEXEC | O_NONBLOCK)`
2. Performs API handshake: `ufd_check_and_apply()` — negotiates features like
   `UFFD_FEATURE_THREAD_ID` (needed for blocktime tracking)
3. Creates an eventfd for signaling the fault thread to quit
4. Starts the fault thread: `postcopy_ram_fault_thread()`
5. Registers all RAMBlocks with `UFFDIO_REGISTER_MODE_MISSING`
   (`ram_block_enable_notify()`). Also checks whether `UFFDIO_ZEROPAGE` is
   supported per-block (it isn't for hugetlbfs)
6. Allocates temporary page buffers for receiving pages
7. Optionally starts a preempt thread for high-priority page requests

### 5.3 Fault Thread Architecture

`postcopy_ram_fault_thread()` (`migration/postcopy-ram.c:1275`) is a dedicated
thread that multiplexes:

- The primary uffd fd (index 0)
- A quit eventfd (index 1)
- Zero or more shared-memory fds from external processes like vhost-user
  (indices 2+)

```c
while (true) {
    poll_result = poll(pfd, pfd_len, -1);

    // Check quit signal
    if (pfd[1].revents) {
        if (fault_thread_quit) break;
    }

    // Handle primary uffd faults
    if (pfd[0].revents) {
        read(mis->userfault_fd, &msg, sizeof(msg));
        rb = qemu_ram_block_from_host(msg.arg.pagefault.address, ...);
        rb_offset = ROUND_DOWN(rb_offset, qemu_ram_pagesize(rb));
        postcopy_request_page(mis, rb, rb_offset, address, ptid);
    }

    // Handle shared memory faults
    for (index = 2; index < pfd_len; index++) {
        if (pfd[index].revents) {
            pcfd->handler(pcfd, &msg);
        }
    }
}
```

### 5.4 Page Request and Resolution Chain

1. **Fault detected**: vCPU accesses unmapped page → kernel delivers
   `UFFD_EVENT_PAGEFAULT` to the uffd fd
2. **Fault thread reads event**: translates HVA → RAMBlock + offset
3. **Check if already received**: `ramblock_recv_bitmap_test()` — if the page
   arrived between fault and processing, skip
4. **Check if discarded**: if the page is in a discard region, place a zero page
   locally via `postcopy_place_page_zero()`
5. **Request from source**: `migrate_send_rp_req_pages()` sends a page request
   on the return path (destination → source channel)
6. **Source sends page**: source scans its dirty bitmap, sends the page data on
   the regular or preempt channel
7. **Destination receives**: `ram_load_postcopy()` reads RAMBlock ID + offset +
   page data
8. **Page placed**: `postcopy_place_page()` calls `qemu_ufd_copy_ioctl()` which
   issues `UFFDIO_COPY` (or `UFFDIO_ZEROPAGE` for zero pages)
9. **Fault resolved**: the `UFFDIO_COPY` atomically maps the page and wakes the
   blocked vCPU thread

### 5.5 Preemption Mode

Enabled via `migrate_postcopy_preempt()`, this creates a second channel
(`RAM_CHANNEL_POSTCOPY`) dedicated to pages that caused actual faults. Without
preemption, a faulted page request can get stuck behind a large batch of
background page transfers on the single channel (head-of-line blocking).

The preempt thread (`postcopy_preempt_thread()`, `migration/postcopy-ram.c:2036`)
reads exclusively from the high-priority channel:

```c
while (preempt_thread_should_run(mis)) {
    ram_load_postcopy(mis->postcopy_qemufile_dst, RAM_CHANNEL_POSTCOPY);
}
```

---

## 6. The userfaultfd Abstraction Layer

`util/userfaultfd.c` provides a clean C API over the kernel interface. All uffd
interactions in QEMU go through these functions:

| Function | Kernel Operation | Notes |
|---|---|---|
| `uffd_open(flags)` | `/dev/userfaultfd` ioctl or `__NR_userfaultfd` syscall | Auto-detects best method on first call |
| `uffd_query_features(features)` | `UFFDIO_API` (probe) | Opens/closes a temporary fd |
| `uffd_create_fd(features, non_blocking)` | `UFFDIO_API` (handshake) | Validates `REGISTER`/`UNREGISTER` support |
| `uffd_register_memory(fd, addr, len, mode, ioctls)` | `UFFDIO_REGISTER` | Returns supported ioctl bitmask |
| `uffd_unregister_memory(fd, addr, len)` | `UFFDIO_UNREGISTER` | |
| `uffd_change_protection(fd, addr, len, wp, dont_wake)` | `UFFDIO_WRITEPROTECT` | `dont_wake` enables batching |
| `uffd_copy_page(fd, dst, src, len, dont_wake)` | `UFFDIO_COPY` | Atomically resolves missing-page fault |
| `uffd_zero_page(fd, addr, len, dont_wake)` | `UFFDIO_ZEROPAGE` | Not supported on hugetlbfs |
| `uffd_wakeup(fd, addr, len)` | `UFFDIO_WAKE` | Wake after batched DONTWAKE operations |
| `uffd_read_events(fd, msgs, count)` | `read()` | Handles `EINTR`, returns 0 on `EAGAIN` |

### Capability Detection

`ram_write_tracking_available()` (`migration/ram.c:1526`) probes for
`UFFD_FEATURE_PAGEFAULT_FLAG_WP` support. `ram_write_tracking_compatible()`
goes further: it opens a real uffd fd, registers every writable RAMBlock in
WP mode, and checks that `UFFDIO_WRITEPROTECT` is in the supported ioctl set.
This catches cases where the kernel supports WP in general but not for a
specific memory type (e.g. shared memory, device memory).

---

## 7. Dirty Tracking Without Hardware Dirty Logging

Traditional QEMU live migration uses hardware dirty logging (KVM's
`KVM_GET_DIRTY_LOG` or dirty ring) to track which pages the guest modified
between iteration rounds. This has several costs:

- Periodic `KVM_GET_DIRTY_LOG` ioctls (one per memslot per sync)
- Large kernel-side bitmaps
- Pages can be dirtied multiple times between syncs, leading to redundant
  transfers
- The snapshot reflects the state at *completion*, not initiation

Background snapshots with UFFD-WP avoid all of these:

- **No hardware dirty logging**: the bitmap starts all-1s and bits are cleared
  as pages are saved. No syncing needed.
- **No redundant transfers**: each page is saved exactly once. If the guest
  writes a page after it's been saved, the write succeeds without trapping
  (protection was already removed). If the guest writes before save, the fault
  blocks the guest, the page is saved in its pre-write state, then the guest's
  write proceeds — but this page is never re-sent.
- **Point-in-time consistency**: the snapshot reflects the VM state at the
  instant write-protection was enabled, regardless of how long the save takes.

The tradeoff is that write faults are more expensive than dirty-log entries.
Each fault involves a kernel→userspace context switch, plus the guest thread is
blocked until the page is saved and flushed. For write-heavy workloads, this can
cause significant vCPU stalls.

---

## 8. Page Fault Resolution and Page Placement

### 8.1 Background Snapshot (WP faults)

Resolution is implicit: the migration thread saves the page to the stream, then
calls `uffd_change_protection(fd, addr, len, false, false)`. The kernel removes
the write-protection and wakes any thread blocked on a write fault in that range.

The key ordering constraint: **flush before unprotect**. From
`ram_save_release_protection()`:

```c
qemu_fflush(pss->pss_channel);      // Ensure page data is committed
uffd_change_protection(rs->uffdio_fd, page_address, run_length, false, false);
```

If the stream write were still buffered when the protection was lifted, a racing
guest write could modify the page before it's flushed, corrupting the snapshot.

### 8.2 Postcopy (Missing-page faults)

Resolution uses `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` via `qemu_ufd_copy_ioctl()`
(`migration/postcopy-ram.c:1587`):

```c
if (from_addr) {
    ret = uffd_copy_page(userfault_fd, host_addr, from_addr, pagesize, false);
} else {
    ret = uffd_zero_page(userfault_fd, host_addr, pagesize, false);
}
```

After a successful copy:

1. The receive bitmap is updated: `ramblock_recv_bitmap_set_range()`
2. If this page was in the pending-request tree, it's removed and the request
   count decremented
3. Blocktime accounting is finalized: `mark_postcopy_blocktime_end()`
4. External shared-memory clients are notified: `postcopy_notify_shared_wake()`

For hugetlbfs pages, `UFFDIO_ZEROPAGE` is not supported. QEMU falls back to
`UFFDIO_COPY` from a pre-allocated zero-filled temporary page
(`mis->postcopy_tmp_zero_page`).

### 8.3 Temporary Pages for Huge Page Assembly

Guest pages can be smaller than host pages (e.g. 4K guest on 2M hugepage host).
Multiple guest pages must be assembled into a single host page before it can be
placed. Each channel has a `PostcopyTmpPage` buffer allocated at setup:

```c
temp_page = mmap(NULL, mis->largest_page_size,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

Guest pages are received into this temporary buffer. When all sub-pages of a
host page have arrived, the entire host page is placed via a single
`UFFDIO_COPY`.

---

## 9. Blocktime Instrumentation

When `UFFD_FEATURE_THREAD_ID` is available (requires kernel support), postcopy
tracks how long each vCPU thread is blocked waiting for a page. This is critical
for understanding the performance impact of postcopy on guest workloads.

### Data structures

`PostcopyBlocktimeContext` (`migration/postcopy-ram.c:123`):

```c
typedef struct PostcopyBlocktimeContext {
    uint64_t *vcpu_blocktime_total;    // Per-vCPU cumulative block time (ns)
    uint64_t *vcpu_faults_count;       // Per-vCPU fault count
    uint8_t  *vcpu_faults_current;     // Currently outstanding faults per vCPU
    GHashTable *vcpu_addr_hash;        // addr → list of (vCPU, timestamp) entries
    uint64_t latency_buckets[24];      // Histogram: bucket[i] = faults with 2^i μs latency
    uint64_t total_blocktime;          // System-wide blocktime (all vCPUs stalled)
    uint64_t last_begin;               // Timestamp when all vCPUs became blocked
    int smp_cpus_down;                 // Count of currently blocked vCPUs
    GHashTable *tid_to_vcpu_hash;      // thread_id → vCPU index (fast lookup)
    uint64_t non_vcpu_blocktime_total; // Block time from non-vCPU threads
    uint64_t non_vcpu_faults;          // Fault count from non-vCPU threads
} PostcopyBlocktimeContext;
```

### Flow

1. **Fault begins** (`mark_postcopy_blocktime_begin`): looks up the faulting
   thread ID in `tid_to_vcpu_hash`, records the timestamp in `vcpu_addr_hash`
   keyed by the faulting address. If all vCPUs are now blocked, records
   `last_begin` for system-wide blocktime.

2. **Fault resolved** (`mark_postcopy_blocktime_end`): for each vCPU that was
   blocked on the resolved address, computes `latency = now - fault_time`,
   accumulates into `vcpu_blocktime_total`, and places into the appropriate
   `latency_buckets[floor(log2(latency_μs))]` bucket. If previously all vCPUs
   were blocked and now some are freed, adds `(now - last_begin)` to
   `total_blocktime`.

### Exposed metrics

The metrics are exposed via QMP `query-migrate` response:

- `postcopy-blocktime`: total system-wide blocktime (ms)
- `postcopy-vcpu-blocktime`: per-vCPU blocktime list (ms)
- `postcopy-latency`: average page fault latency (ns)
- `postcopy-vcpu-latency`: per-vCPU average latency (ns)
- `postcopy-latency-dist`: histogram of latencies (24 power-of-2 μs buckets)
- `postcopy-non-vcpu-latency`: average latency for non-vCPU thread faults (ns)

---

## 10. Design Tradeoffs and Pitfalls

### 10.1 Page Population Cost

`ram_write_tracking_prepare()` must read every page of guest RAM to ensure PTEs
exist. For a 64GB VM, this means touching 16 million 4K pages. This is done
serially and can take seconds. It happens while the VM is still running (before
the brief pause), so it doesn't add to downtime, but it does add to total
snapshot time and can cause memory pressure (all pages become resident).

### 10.2 Write Fault Latency

Each uffd write fault involves:
1. Guest write traps to kernel
2. Kernel suspends faulting thread, delivers message to uffd fd
3. Migration thread (which may be busy saving other pages) eventually reads the
   event
4. Migration thread saves the faulted page to the stream
5. Migration thread flushes the stream
6. Migration thread issues `UFFDIO_WRITEPROTECT` to remove protection
7. Kernel wakes the faulting thread

Steps 3-5 are the bottleneck. If the migration thread is in the middle of saving
a different page (or a range of pages), the faulting vCPU is stalled until that
completes. QEMU mitigates this by checking for write faults in the inner loop
(`get_queued_page()` calls `poll_fault_page()`), but there's no preemption
within a page save operation.

### 10.3 BH Resume to Avoid Deadlock

As described in section 4.9, the VM must be resumed from a bottom-half to avoid
deadlocking when state-change notifiers write to protected memory. Any VMM
implementing a similar scheme must be careful about what code runs between
enabling write-protection and starting the save loop.

### 10.4 RamDiscardManager Interaction

Virtio-mem and similar hotplug devices use `RamDiscardManager` to track which
sub-ranges of a RAMBlock are "populated" (in use by the guest) vs "discarded".
Both page population and write-protection must only apply to populated ranges:

```c
if (rb->mr && memory_region_has_ram_discard_manager(rb->mr)) {
    ram_discard_manager_replay_populated(rdm, &section,
                                         uffd_protect_section, ...);
} else {
    uffd_change_protection(uffd_fd, rb->host, rb->used_length, true, false);
}
```

Protecting discarded ranges could cause spurious faults or kernel errors.

### 10.5 Postcopy Pause and Recovery

Network failures during postcopy are not fatal. The fault thread enters a pause
state (`postcopy_pause_fault_thread`), blocking on a semaphore. The QMP command
`migrate-recover` on the destination and `migrate resume=true` on the source
re-establish the connection. The fault thread resumes and retries the failed page
request. Any vCPU threads that faulted during the outage remain blocked (in the
kernel) until their pages are eventually resolved.

### 10.6 DONTWAKE Batching

Both `uffd_copy_page()` and `uffd_zero_page()` accept a `dont_wake` flag. When
set, the ioctl resolves the fault (maps the page) but doesn't wake blocked
threads. After resolving a batch of pages, a single `uffd_wakeup()` call wakes
all threads. QEMU currently doesn't use this for postcopy (each page is resolved
with immediate wake), but the infrastructure is in place for future optimization.

---

## 11. Kernel Version Requirements

| Feature | Minimum Kernel | uffd Feature Flag |
|---|---|---|
| Basic userfaultfd | 4.3 | — |
| Missing-page mode | 4.3 | `UFFD_FEATURE_MISSING_*` |
| `/dev/userfaultfd` device | 6.1 | — |
| Write-protect mode (UFFD-WP) | 5.7 | `UFFD_FEATURE_PAGEFAULT_FLAG_WP` |
| Thread ID in fault messages | 4.9 | `UFFD_FEATURE_THREAD_ID` |
| Hugetlbfs missing-page | 4.11 | `UFFD_FEATURE_MISSING_HUGETLBFS` |
| Shared memory missing-page | 4.11 | `UFFD_FEATURE_MISSING_SHMEM` |
| Write-protect on shmem | 5.19 | Kernel-side, no separate feature flag |

Background snapshots require Linux 5.7+. Postcopy works from 4.3 but benefits
from newer kernels (thread ID tracking, hugetlbfs support).

---

## 12. Key Source Files

| File | Role |
|---|---|
| `util/userfaultfd.c` | uffd abstraction layer (all ioctl wrappers) |
| `include/qemu/userfaultfd.h` | uffd API declarations |
| `migration/ram.c` | RAM save/load, UFFD-WP tracking for background snapshots, dirty bitmap management |
| `migration/postcopy-ram.c` | Postcopy fault thread, page placement (`UFFDIO_COPY`), blocktime tracking, postcopy setup/cleanup |
| `migration/postcopy-ram.h` | Postcopy state machine, PostCopyFD for shared memory |
| `migration/migration.c` | `bg_migration_thread()` orchestration, `bg_migration_completion()` |
| `migration/savevm.c` | VM state serialization framework, snapshot QMP commands |
| `migration/vmstate.c` | Declarative device state serialization |
| `migration/options.c` | `migrate_background_snapshot()` capability check |
| `system/physmem.c` | Physical memory dirty bitmap primitives |
| `linux-headers/linux/userfaultfd.h` | Kernel UAPI structures (`struct uffd_msg`, ioctl definitions) |
