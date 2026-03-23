# Plan: bpf_fault-based Background Snapshot for QEMU

## Context

QEMU's background snapshot (`bg_migration_thread` in `migration/migration.c`) currently uses
userfaultfd write-protect (uffd-WP) to take a point-in-time snapshot of VM RAM while the VM
continues running. When the guest writes to a WP-protected page, the uffd mechanism blocks the
guest thread, the migration thread saves the page, un-protects it, and then the guest thread
resumes. This blocking behavior adds latency to guest writes during the snapshot window.

The `bpf_fault` kernel interface provides a non-blocking alternative: a BPF program runs
synchronously in the faulting thread's context (~7us vs ~200us for uffd), copies the pre-write
page content to a BPF ring buffer, and immediately allows the write. This eliminates the
guest-blocking IPC overhead entirely.

This plan adds a third snapshot mode alongside the existing two (normal paused snapshot and
uffd-WP background snapshot).

## Design Overview

### Single-thread Architecture

One migration thread handles both sequential page saving and ring buffer consumption:

```
1. Pause VM, save non-RAM vmstate to temp buffer
2. Attach bpf_fault with BPF_FAULT_FLAG_WP to all RAM blocks
3. WP-enable all registered pages
4. Resume VM
5. Loop:
   a. Save a batch of N pages (sequential scan of dirty bitmap)
      - For each page: check "captured" bitmap; if set, skip; else read+save, un-protect
   b. Poll BPF ring buffer, drain all available entries
      - For each entry: write page to stream, mark "captured" bitmap, un-protect
   c. Repeat until all pages done
6. Final ring buffer drain
7. Append non-RAM vmstate from temp buffer
8. Destroy bpf_fault link (cleans up remaining WP)
```

### Captured Bitmap (userspace-only, NOT shared with BPF)

A userspace bitmap (one bit per target page per RAMBlock) tracks pages whose pre-write content
has been consumed from the ring buffer and written to the stream. This bitmap lives entirely
in userspace -- the BPF program has no knowledge of it.

**Data flow:**
1. BPF `handle_wp_fault` copies page content into the ring buffer (`{u64 address, u8 data[4096]}`)
   and returns 0. The BPF program is completely stateless beyond the ring buffer.
2. The migration thread's ring buffer consumer calls `ring_buffer__poll()`, and for each entry:
   - Resolves `entry->address` to `(RAMBlock *, offset)` via `qemu_ram_block_from_host()`
   - Writes the page to the migration stream
   - Sets the captured bit for `(block, offset)` in the per-block userspace bitmap
   - Un-protects the page
3. The migration thread's sequential scan checks the bitmap before reading each page:
   - **Bit clear**: page hasn't been dirtied. Read current content, write to stream, un-protect.
   - **Bit set**: BPF already captured correct content via ring buffer. Skip, un-protect only.

Since both the ring buffer consumer and the sequential scan run in the same single thread,
there are no concurrency issues with the bitmap itself.

**Per-block bitmaps with a single BPF link:** The BPF program and link have no per-block
awareness. Ring buffer entries contain raw virtual addresses. The userspace consumer resolves
addresses to `(RAMBlock, offset)` via `qemu_ram_block_from_host()` (which walks `ram_list.blocks`
checking `host <= addr < host + max_length`, with MRU cache). Each RAMBlock has its own
captured bitmap (allocated at `bpf_fault_wp_start()` time, sized `max_length / TARGET_PAGE_SIZE`
bits). All block-level bookkeeping is userspace-only.

**TOCTOU race (BPF fires between bitmap check and page read):** If the migration thread checks
the bitmap (clear), then a BPF fault fires (page copied to ring buffer), then the migration
thread reads the page (gets post-write stale content) -- this is safe. The ring buffer entry
will be consumed in a later poll and written to the stream AFTER the stale read. Since the
migration stream is loaded sequentially and last-write-wins, the ring buffer's correct content
overwrites the stale data on load. This race only adds a redundant page write to the stream.

### BPF Program

The BPF program uses a ring buffer map (`BPF_MAP_TYPE_RINGBUF`, 256MB) to pass page contents
to userspace. Each entry is `{u64 address, u8 data[4096]}`.

On `handle_wp_fault`: reserve ring buffer entry, copy page content via `bpf_probe_read_kernel`,
submit, return 0 (allow write). If ring buffer is full, log via `bpf_printk` and return 0
(allow write, page content lost -- assumed rare).

`handle_page_fault` is NULL (missing faults use normal kernel zero-fill).

### Ring Buffer Overflow

If the ring buffer fills, the BPF program allows the write but cannot capture the page content.
This means the migration thread will later read post-write content for that page -- producing
an inconsistent snapshot. For now this is accepted as unlikely given the 256MB buffer (~64K
pages in flight). A future improvement could add an "overflow" BPF array map that the BPF
program marks on drop, and the migration thread re-protects and re-scans those pages.

## Files to Create

### 1. `migration/bpf_fault_snapshot.bpf.c` -- BPF program

```
- SEC(".maps") ring buffer: BPF_MAP_TYPE_RINGBUF, 256MB
- struct ring_buf_entry { __u64 address; __u8 data[4096]; }
- SEC("struct_ops/handle_wp_fault"): reserve entry, bpf_probe_read_kernel page, submit
- SEC(".struct_ops.link") fault_ops with handle_page_fault = NULL
```

Compiled with clang to produce `bpf_fault_snapshot.bpf.o`, then `bpftool gen skeleton` to
produce `bpf_fault_snapshot.skel.h`.

### 2. `migration/bpf-fault-snapshot.h` -- Header for bpf_fault snapshot interface

Public API:
```c
bool bpf_fault_snapshot_available(void);     /* runtime check */
int  bpf_fault_wp_start(void);               /* attach + register + WP-enable all RAMBlocks */
void bpf_fault_wp_stop(void);                /* destroy link, cleanup */
int  bpf_fault_poll_ring(QEMUFile *f, RAMState *rs);  /* drain ring buffer, write pages */
bool bpf_fault_page_captured(RAMBlock *block, unsigned long page); /* check captured bitmap */
void bpf_fault_release_protection(RAMBlock *block, unsigned long page); /* un-protect single page */
```

### 3. `migration/bpf-fault-snapshot.c` -- Userspace bpf_fault management

Key responsibilities:
- **`bpf_fault_wp_start()`**: Open+load skeleton, iterate `RAMBLOCK_FOREACH_NOT_IGNORED`,
  call `bpf_map__attach_fault_ops()` with `BPF_FAULT_FLAG_WP` for each block, then
  `BPF_FAULT_WP_ENABLE` on the full range. Allocate per-block captured bitmaps.
  Calls `ram_block_populate_read()` (reuse existing, `migration/ram.c:1618`) first to ensure
  PTEs exist (same reason as uffd-WP path).
- **`bpf_fault_wp_stop()`**: `bpf_link__destroy()`, free captured bitmaps.
- **`bpf_fault_poll_ring()`**: `ring_buffer__poll()` with timeout=0. Callback for each entry:
  map `entry->address` to `(RAMBlock, offset)` via `qemu_ram_block_from_host()`
  (`system/physmem.c:2782`), write page to stream using `save_page_header()` +
  `qemu_put_buffer()` (reuse existing wire format from `save_normal_page`,
  `migration/ram.c:1273`), set captured bitmap bit, un-protect the page via
  `BPF_LINK_FAULT_OPS_CMD` with flags=0.
- **`bpf_fault_page_captured()`**: test bit in per-block captured bitmap.
- **Per-block state**: struct holding `bpf_link *`, captured bitmap, block pointer.

Note on multi-region: A single `bpf_link` can manage multiple disjoint regions via
`bpf_link__fault_register()`. So we attach once on the first RAMBlock, then register
additional blocks to the same link. This shares one BPF program instance.

### 4. `migration/bpf-fault-snapshot.bpf.c` build rules

Add to `meson.build`:
- Use `custom_target` to compile `.bpf.c` -> `.bpf.o` with clang
- Use `custom_target` to generate skeleton header via `bpftool gen skeleton`
- Link `libbpf` (use `dependency('libbpf')`)

## Files to Modify

### 5. `migration/ram.c`

**`ram_find_and_save_block()`** (line 2322): In the page-save loop, after `find_dirty_block`
finds a page, check `bpf_fault_page_captured(block, page)`. If captured, skip saving
(clear dirty bit, un-protect, continue). This is analogous to how `poll_fault_page()` currently
works for uffd-WP but inverted -- instead of blocking on fault, we proactively skip captured pages.

**`ram_save_host_page()`** (line 2223): Before `ram_save_target_page`, check captured bitmap.
If page captured, skip the save, just advance. Still call `ram_save_release_protection()` path
but using `bpf_fault_release_protection()` instead of `uffd_change_protection()`.

**`ram_save_iterate()`** (line 3256): Between batch iterations (inside the while loop, perhaps
every 64 iterations alongside the existing time check), call `bpf_fault_poll_ring()` to drain
the ring buffer and write those pages to the stream.

**`ram_write_tracking_start()`** (line 1711): Add conditional: if bpf_fault mode, call
`bpf_fault_wp_start()` instead of uffd setup.

**`ram_write_tracking_stop()`** (line 1772): Add conditional: if bpf_fault mode, call
`bpf_fault_wp_stop()` instead of uffd teardown.

**`ram_save_release_protection()`** (line 1502): Add conditional: if bpf_fault mode, call
`bpf_fault_release_protection()` instead of `uffd_change_protection()`.

**`poll_fault_page()`** (line 1470): This function is uffd-specific (reads uffd events to find
faulted pages for priority saving). For bpf_fault mode, it should return NULL (no blocking
faults to prioritize). Add early return if bpf_fault mode.

### 6. `migration/migration.c`

**`bg_migration_thread()`** (line 3613): Modify to support bpf_fault:
- The overall structure stays the same (pause, save non-RAM state, start WP tracking, resume,
  iterate, complete).
- `ram_write_tracking_prepare()` and `ram_write_tracking_start()` already dispatch to the
  right backend (step 5 above).
- In the main loop, `bg_migration_iteration_run()` calls `qemu_savevm_state_iterate()` which
  calls `ram_save_iterate()` -- the ring buffer polling is integrated there.
- After the loop, add a final `bpf_fault_poll_ring()` drain call before completion.

**`bg_migration_iteration_finish()`** (line 3346): `ram_write_tracking_stop()` already
dispatches (step 5 above).

### 7. `migration/options.c`

Add a new migration parameter (not capability) to select the WP backend:
`x-background-snapshot-mode` with values `uffd` (default) and `bpf-fault`.

Or simpler: a boolean `x-bpf-fault-snapshot` parameter. Add `migrate_bpf_fault_snapshot()`
accessor. Gate it on `background-snapshot` capability being enabled.

### 8. `qapi/migration.json`

Add the new parameter to `MigrationParameter` / `MigrationParameters`. Add documentation.

### 9. `migration/ram.c` -- New flag

Add `RAM_BPF_FAULT_WP` flag (parallel to `RAM_UF_WRITEPROTECT`) to `RAMBlock.flags` to
track which blocks are registered with bpf_fault. This is used in conditionals throughout
the save path.

### 10. `meson.build`

- Add `libbpf` dependency
- Add BPF compilation targets (clang + bpftool skeleton generation)
- Add `migration/bpf-fault-snapshot.c` to migration sources

## Key Edge Cases

1. **Pages dirtied before migration thread reaches them**: Handled by captured bitmap.
   BPF captures pre-write content, migration thread skips those pages.

2. **Torn reads**: If migration thread reads a page concurrently with a guest write,
   the read may be inconsistent. But if the guest wrote, BPF captured the correct content
   and the captured bitmap will be set. The migration thread checks the bitmap before saving,
   so it will skip the page. There's a tiny TOCTOU window (check bitmap -> read page), but
   the cost is writing one extra copy of the page (the later ring buffer entry wins on load).
   Actually -- the bitmap is set by the ring buffer consumer which IS the migration thread,
   so the check and the set are single-threaded. The race is: BPF fires between bitmap check
   and page read. The page gets modified. Migration thread reads stale data and writes it.
   Later, ring buffer drain writes correct data. On load, the stream is sequential and
   last-write-wins, so the ring buffer entry (written later in the stream) overwrites.
   This is correct.

3. **RAM hotplug during snapshot**: Existing code handles this via `ram_list.version` check
   in `ram_save_iterate()`. For bpf_fault, newly added RAMBlocks would need to be registered
   with the existing bpf_link via `bpf_link__fault_register()`. This is a future enhancement;
   for now, block RAM hotplug during bpf_fault snapshot (same practical limitation as uffd-WP).

4. **Discarded pages (virtio-mem)**: Reuse `ram_block_populate_read()`'s existing
   `RamDiscardManager` logic to skip discarded regions during bpf_fault registration.

5. **Read-only / ROM blocks**: Skip during registration, same as uffd-WP path
   (`block->mr->readonly || block->mr->rom_device`).

6. **Ring buffer sizing**: 256MB supports ~64K in-flight dirty pages. For VMs with very high
   write rates, this may need tuning. Could be exposed as a migration parameter later.

## Performance Considerations

- **No guest blocking**: Unlike uffd-WP where the faulting thread blocks until the page is
  saved, bpf_fault allows the write immediately (~7us fault latency vs ~200us). This is the
  primary performance win.
- **Ring buffer batching**: `ring_buffer__poll()` with timeout=0 drains all available entries
  in one go, amortizing syscall overhead.
- **Single-thread simplicity**: No synchronization overhead between threads. The captured
  bitmap is accessed only by the migration thread.
- **Duplicate page writes**: In the TOCTOU race case, a page may be written twice to the
  stream. This is rare and acceptable -- last-write-wins semantics on load handle it correctly.

## Verification

1. **Unit test**: Add a test in `tests/qtest/migration/` that enables both `background-snapshot`
   capability and `x-bpf-fault-snapshot` parameter, runs a snapshot, and verifies the VM
   state loads correctly.
2. **Functional test**: Run a write-heavy guest workload during snapshot and verify snapshot
   integrity by loading it.
3. **Ring buffer overflow test**: Artificially reduce ring buffer size and verify the snapshot
   still completes (with logged warnings about dropped pages).
4. **Compatibility test**: Verify existing uffd-WP background snapshot still works unchanged.
5. **Build test**: Verify `meson setup` with and without libbpf available.
