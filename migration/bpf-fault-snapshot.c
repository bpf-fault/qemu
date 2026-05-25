/*
 * bpf_fault-based background snapshot for QEMU migration
 *
 * Uses the bpf_fault kernel interface to capture pre-write page content
 * via a BPF ring buffer, providing a non-blocking alternative to
 * userfaultfd write-protect for background snapshots.
 *
 * Copyright (c) 2024
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bitmap.h"
#include "exec/target_page.h"
#include "system/ramblock.h"
#include "system/memory.h"
#include "bpf-fault-snapshot.h"
#include "migration/misc.h"
#include "ram.h"
#include "qemu-file.h"
#include "migration-stats.h"

#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_fault_snapshot.bpf.skeleton.h"

/*
 * bpf_fault UAPI constants - defined here until they propagate to
 * system headers.
 */
#ifndef BPF_LINK_FAULT_OPS_CMD
#define BPF_LINK_FAULT_OPS_CMD 38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP      (1U << 0)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE    (1U << 0)
#endif

struct bpf_link_fault_cmd_attr {
    uint32_t link_fd;
    uint32_t flags;
    uint64_t start;
    uint64_t len;
} __attribute__((aligned(8)));

typedef struct BpfFaultBlockState {
    RAMBlock *block;
    struct bpf_link *link;           /* fault_ops link for this block */
    unsigned long *captured_bitmap;  /* one bit per target page */
    unsigned long num_pages;
} BpfFaultBlockState;

/*
 * Threshold for flushing the deferred WP-release range. Each
 * bpf_link_writeprotect() call broadcasts a TLB-IPI to every CPU running the
 * guest mm; with per-page release that's one IPI per dirty target page,
 * which dominates guest throughput during a snapshot. Batching into 16 MiB
 * runs matches Firecracker's LINEAR_BATCH and keeps the IPI rate down by
 * 4096x for 4 KiB pages.
 */
#define BPF_FAULT_RELEASE_BATCH_PAGES 4096   /* 16 MiB at 4 KiB target page */

static struct {
    struct bpf_fault_snapshot_bpf *skel;
    struct ring_buffer *ringbuf;
    BpfFaultBlockState *block_states;
    int num_blocks;
    /* Set during poll_ring for callback context */
    QEMUFile *current_file;
    RAMBlock *last_sent_block;
    int pages_written;
    /* MRU cache for find_block_state — ring buffer entries are typically
     * clustered by RAMBlock, so this short-circuits the linear search. */
    RAMBlock *last_resolved_block;
    BpfFaultBlockState *last_resolved_bs;
    /* Deferred wp-release range. Coalesced across contiguous calls and
     * flushed when the run is full, the block changes, or callers force
     * a flush. */
    RAMBlock *pending_release_block;
    unsigned long pending_release_start;
    unsigned long pending_release_npages;
} bpf_state;

static int bpf_link_writeprotect(int link_fd, uint64_t start, uint64_t len,
                                  uint32_t flags)
{
    struct bpf_link_fault_cmd_attr attr = {
        .link_fd = link_fd,
        .flags = flags,
        .start = start,
        .len = len,
    };

    return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

/**
 * find_block_state: locate the BpfFaultBlockState for a given RAMBlock
 */
static BpfFaultBlockState *find_block_state(RAMBlock *block)
{
    if (bpf_state.last_resolved_block == block) {
        return bpf_state.last_resolved_bs;
    }

    for (int i = 0; i < bpf_state.num_blocks; i++) {
        if (bpf_state.block_states[i].block == block) {
            bpf_state.last_resolved_block = block;
            bpf_state.last_resolved_bs = &bpf_state.block_states[i];
            return &bpf_state.block_states[i];
        }
    }

    bpf_state.last_resolved_block = block;
    bpf_state.last_resolved_bs = NULL;
    return NULL;
}

/**
 * bpf_fault_write_page: write a captured page to the migration stream
 *
 * Writes the page header (offset + block identification) followed by
 * the page data in the standard QEMU migration wire format.
 */
static void bpf_fault_write_page(QEMUFile *f, RAMBlock *block,
                                  ram_addr_t offset, const uint8_t *data)
{
    ram_addr_t wire_offset = offset | RAM_SAVE_FLAG_PAGE;
    bool same_block = (block == bpf_state.last_sent_block);

    if (same_block) {
        wire_offset |= RAM_SAVE_FLAG_CONTINUE;
    }
    qemu_put_be64(f, wire_offset);

    if (!same_block) {
        size_t len = strlen(block->idstr);
        qemu_put_byte(f, len);
        qemu_put_buffer(f, (uint8_t *)block->idstr, len);
        bpf_state.last_sent_block = block;
    }

    qemu_put_buffer(f, data, TARGET_PAGE_SIZE);
    ram_transferred_add(TARGET_PAGE_SIZE);
}

/**
 * ring_buf_callback: called for each entry in the BPF ring buffer
 *
 * Resolves the faulting address to a RAMBlock, writes the captured
 * page to the migration stream, and marks it in the captured bitmap.
 */
static int ring_buf_callback(void *ctx, void *data, size_t data_sz)
{
    uint64_t address;
    const uint8_t *page_data;
    RAMBlock *block;
    ram_addr_t offset;
    BpfFaultBlockState *bs;
    unsigned long page;

    if (data_sz < sizeof(uint64_t) + TARGET_PAGE_SIZE) {
        return 0;
    }

    address = *(uint64_t *)data;
    page_data = (const uint8_t *)data + sizeof(uint64_t);

    block = qemu_ram_block_from_host((void *)(uintptr_t)address, false,
                                     &offset);
    if (!block) {
        error_report("bpf_fault: cannot resolve address 0x%" PRIx64, address);
        return 0;
    }

    bs = find_block_state(block);
    if (!bs) {
        return 0;
    }

    page = offset >> TARGET_PAGE_BITS;
    if (page >= bs->num_pages) {
        return 0;
    }

    /* Write page to migration stream */
    bpf_fault_write_page(bpf_state.current_file, block, offset, page_data);

    /* Mark page as captured */
    set_bit(page, bs->captured_bitmap);
    bpf_state.pages_written++;

    return 0;
}

bool bpf_fault_snapshot_available(void)
{
    struct bpf_fault_snapshot_bpf *skel;
    int ret;

    skel = bpf_fault_snapshot_bpf__open();
    if (!skel) {
        return false;
    }
    ret = bpf_fault_snapshot_bpf__load(skel);
    bpf_fault_snapshot_bpf__destroy(skel);
    return ret == 0;
}

int bpf_fault_wp_prepare(void)
{
    memset(&bpf_state, 0, sizeof(bpf_state));

    /* Open and load BPF program — this runs the verifier (expensive) */
    bpf_state.skel = bpf_fault_snapshot_bpf__open_and_load();
    if (!bpf_state.skel) {
        error_report("bpf_fault: failed to open and load BPF skeleton");
        return -1;
    }

    /* Create ring buffer consumer early — no data arrives until WP is on */
    bpf_state.ringbuf = ring_buffer__new(
        bpf_map__fd(bpf_state.skel->maps.ring_buf),
        ring_buf_callback, NULL, NULL);
    if (!bpf_state.ringbuf) {
        error_report("bpf_fault: failed to create ring buffer consumer");
        bpf_fault_snapshot_bpf__destroy(bpf_state.skel);
        bpf_state.skel = NULL;
        return -1;
    }

    return 0;
}

int bpf_fault_wp_start(void)
{
    RAMBlock *block;
    int num_blocks = 0;

    if (!bpf_state.skel) {
        error_report("bpf_fault: skeleton not loaded, "
                     "call bpf_fault_wp_prepare() first");
        return -1;
    }

    /* Count eligible RAM blocks */
    RCU_READ_LOCK_GUARD();

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        if (block->mr->readonly || block->mr->rom_device) {
            continue;
        }
        num_blocks++;
    }

    bpf_state.block_states = g_new0(BpfFaultBlockState, num_blocks);
    bpf_state.num_blocks = 0;

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        BpfFaultBlockState *bs;
        struct bpf_link *link;
        unsigned long num_pages;
        int link_fd;

        if (block->mr->readonly || block->mr->rom_device) {
            continue;
        }

        /*
         * Page tables are pre-populated by ram_write_tracking_prepare()
         * which is called before ram_write_tracking_start().
         *
         * Attach fault_ops to this block's memory region with WP flag.
         */
        link = bpf_map__attach_fault_ops(
            bpf_state.skel->maps.snapshot_fault_ops,
            block->host, block->used_length, BPF_FAULT_FLAG_WP);
        if (!link) {
            error_report("bpf_fault: failed to attach fault_ops "
                         "for block %s: %s",
                         block->idstr, strerror(errno));
            goto fail;
        }

        /* Enable write-protection on the used range */
        link_fd = bpf_link__fd(link);
        if (bpf_link_writeprotect(link_fd, (uintptr_t)block->host,
                                   block->used_length,
                                   BPF_FAULT_WP_ENABLE) < 0) {
            error_report("bpf_fault: failed to enable WP for block %s: %s",
                         block->idstr, strerror(errno));
            bpf_link__destroy(link);
            goto fail;
        }

        block->flags |= RAM_BPF_FAULT_WP;
        memory_region_ref(block->mr);

        /* Set up per-block state */
        num_pages = block->used_length >> TARGET_PAGE_BITS;
        if (!num_pages) {
            bpf_link__destroy(link);
            block->flags &= ~RAM_BPF_FAULT_WP;
            memory_region_unref(block->mr);
            continue;
        }
        bs = &bpf_state.block_states[bpf_state.num_blocks];
        bs->block = block;
        bs->link = link;
        bs->num_pages = num_pages;
        bs->captured_bitmap = bitmap_new(num_pages);
        bpf_state.num_blocks++;
    }

    return 0;

fail:
    /* Clean up on failure */
    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        if (!(block->flags & RAM_BPF_FAULT_WP)) {
            continue;
        }
        block->flags &= ~RAM_BPF_FAULT_WP;
        memory_region_unref(block->mr);
    }

    for (int i = 0; i < bpf_state.num_blocks; i++) {
        if (bpf_state.block_states[i].link) {
            bpf_link__destroy(bpf_state.block_states[i].link);
        }
        g_free(bpf_state.block_states[i].captured_bitmap);
    }
    g_free(bpf_state.block_states);
    bpf_state.block_states = NULL;
    bpf_state.num_blocks = 0;
    bpf_state.last_resolved_block = NULL;
    bpf_state.last_resolved_bs = NULL;

    if (bpf_state.ringbuf) {
        ring_buffer__free(bpf_state.ringbuf);
        bpf_state.ringbuf = NULL;
    }
    bpf_fault_snapshot_bpf__destroy(bpf_state.skel);
    bpf_state.skel = NULL;

    return -1;
}

void bpf_fault_wp_stop(void)
{
    RAMBlock *block;

    /* Flush any deferred WP-release before the links go away — issue_release
     * uses find_block_state, which relies on bpf_state.block_states still
     * being valid. Errors are reported but cleanup must continue. The stream
     * is done by this point so no QEMUFile fflush is needed. */
    (void)bpf_fault_release_protection_flush(NULL);

    if (bpf_state.ringbuf) {
        ring_buffer__free(bpf_state.ringbuf);
        bpf_state.ringbuf = NULL;
    }

    RCU_READ_LOCK_GUARD();

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        if (!(block->flags & RAM_BPF_FAULT_WP)) {
            continue;
        }
        block->flags &= ~RAM_BPF_FAULT_WP;
        memory_region_unref(block->mr);
    }

    for (int i = 0; i < bpf_state.num_blocks; i++) {
        if (bpf_state.block_states[i].link) {
            bpf_link__destroy(bpf_state.block_states[i].link);
        }
        g_free(bpf_state.block_states[i].captured_bitmap);
    }
    g_free(bpf_state.block_states);
    bpf_state.block_states = NULL;
    bpf_state.num_blocks = 0;
    bpf_state.last_resolved_block = NULL;
    bpf_state.last_resolved_bs = NULL;

    if (bpf_state.skel) {
        bpf_fault_snapshot_bpf__destroy(bpf_state.skel);
        bpf_state.skel = NULL;
    }

    bpf_state.last_sent_block = NULL;
}

int bpf_fault_poll_ring(QEMUFile *f)
{
    int ret;

    if (!bpf_state.ringbuf) {
        return 0;
    }

    bpf_state.current_file = f;
    bpf_state.pages_written = 0;

    /*
     * Use ring_buffer__consume instead of ring_buffer__poll(rb, 0): poll()
     * always issues epoll_wait, even for a 0 timeout, which is a wasted
     * syscall when we just want to drain any already-published records. The
     * BPF program submits with BPF_RB_NO_WAKEUP, so there is no event to
     * wait for anyway — consume() walks the consumer/producer cursors in
     * the mmap'd metadata pages and runs the callback for each record.
     */
    ret = ring_buffer__consume(bpf_state.ringbuf);
    if (ret < 0 && ret != -EINTR) {
        error_report("bpf_fault: ring buffer consume error: %s",
                     strerror(-ret));
        return ret;
    }

    bpf_state.current_file = NULL;
    return bpf_state.pages_written;
}

bool bpf_fault_page_captured(RAMBlock *block, unsigned long page)
{
    BpfFaultBlockState *bs = find_block_state(block);

    if (!bs || page >= bs->num_pages) {
        return false;
    }

    return test_bit(page, bs->captured_bitmap);
}

uint64_t bpf_fault_ringbuf_drop_count(void)
{
    int map_fd, n_cpus;
    uint32_t key = 0;
    uint64_t total = 0;
    uint64_t *values = NULL;

    if (!bpf_state.skel) {
        return 0;
    }

    map_fd = bpf_map__fd(bpf_state.skel->maps.drop_counter);
    if (map_fd < 0) {
        return 0;
    }

    n_cpus = libbpf_num_possible_cpus();
    if (n_cpus <= 0) {
        return 0;
    }

    values = g_new0(uint64_t, n_cpus);
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
        for (int i = 0; i < n_cpus; i++) {
            total += values[i];
        }
    }
    g_free(values);
    return total;
}

/*
 * issue_release: do the actual bpf() syscall for one (block, start, npages).
 * This is the only place that calls into the kernel; bpf_fault_release_protection
 * and bpf_fault_release_protection_flush funnel into it.
 */
static int issue_release(RAMBlock *block, unsigned long start_page,
                         unsigned long npages)
{
    BpfFaultBlockState *bs;
    void *page_address;
    uint64_t run_length;
    int link_fd;

    bs = find_block_state(block);
    if (!bs || !bs->link) {
        error_report("bpf_fault: missing link state while resolving WP for %s",
                     block ? block->idstr : "<null>");
        return -1;
    }

    if (start_page >= bs->num_pages || npages > bs->num_pages - start_page) {
        error_report("bpf_fault: invalid WP resolve range for %s "
                     "(start_page=%lu npages=%lu num_pages=%lu)",
                     block->idstr, start_page, npages, bs->num_pages);
        return -1;
    }

    page_address = block->host + (start_page << TARGET_PAGE_BITS);
    run_length = npages << TARGET_PAGE_BITS;
    link_fd = bpf_link__fd(bs->link);

    if (bpf_link_writeprotect(link_fd, (uintptr_t)page_address,
                               run_length, 0) < 0) {
        error_report("bpf_fault: failed to resolve WP for block %s: %s",
                     block->idstr, strerror(errno));
        return -1;
    }

    return 0;
}

int bpf_fault_release_protection_flush(QEMUFile *f)
{
    RAMBlock *block = bpf_state.pending_release_block;
    unsigned long start = bpf_state.pending_release_start;
    unsigned long npages = bpf_state.pending_release_npages;
    int ret;

    if (!block || !npages) {
        bpf_state.pending_release_block = NULL;
        bpf_state.pending_release_npages = 0;
        return 0;
    }

    /* Clear pending state before the syscall so a partial failure can't be
     * re-flushed against stale state. */
    bpf_state.pending_release_block = NULL;
    bpf_state.pending_release_start = 0;
    bpf_state.pending_release_npages = 0;

    /* Commit any async-queued page bytes (save_normal_page uses
     * qemu_put_buffer_async, which only stashes a pointer) to the migration
     * stream BEFORE telling the kernel to drop WP. Otherwise the guest can
     * race in between the wp-clear and the eventual writev and we'd write
     * post-write content for some pages without a ring-buffer override. */
    if (f) {
        qemu_fflush(f);
    }

    ret = issue_release(block, start, npages);
    return ret;
}

int bpf_fault_release_protection(QEMUFile *f, RAMBlock *block,
                                  unsigned long start_page,
                                  unsigned long npages)
{
    int ret;

    if (!npages) {
        return 0;
    }

    /* Coalesce with the pending range if same block and immediately adjacent. */
    if (bpf_state.pending_release_block == block &&
        bpf_state.pending_release_start + bpf_state.pending_release_npages
            == start_page) {
        bpf_state.pending_release_npages += npages;
    } else {
        /* Different block or non-contiguous: flush the previous run first. */
        ret = bpf_fault_release_protection_flush(f);
        if (ret < 0) {
            return ret;
        }
        bpf_state.pending_release_block = block;
        bpf_state.pending_release_start = start_page;
        bpf_state.pending_release_npages = npages;
    }

    if (bpf_state.pending_release_npages >= BPF_FAULT_RELEASE_BATCH_PAGES) {
        return bpf_fault_release_protection_flush(f);
    }
    return 0;
}
