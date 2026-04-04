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
#include "qemu/bswap.h"
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

static struct {
    struct bpf_fault_snapshot_bpf *skel;
    struct ring_buffer *ringbuf;
    BpfFaultBlockState *block_states;
    int num_blocks;
    GByteArray *ring_batch;
    /* Set during poll_ring for callback context */
    QEMUFile *current_file;
    RAMBlock **current_last_sent_block;
    RAMBlock *last_resolved_block;
    BpfFaultBlockState *last_resolved_bs;
    int pages_written;
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
 * bpf_fault_batch_append_page: append a captured page in migration wire format
 *
 * Serializes the page header (offset + block identification) followed by
 * the page data into the per-poll batch buffer. The batch is handed off to
 * QEMUFile asynchronously once ring polling finishes, so we avoid immediate
 * per-page writes while keeping the wire format unchanged.
 */
static void bpf_fault_batch_append_page(RAMBlock *block, ram_addr_t offset,
                                        const uint8_t *data)
{
    ram_addr_t wire_offset = offset | RAM_SAVE_FLAG_PAGE;
    RAMBlock **last_sent_block = bpf_state.current_last_sent_block;
    bool same_block = last_sent_block && (block == *last_sent_block);
    uint8_t be64_buf[sizeof(uint64_t)];

    if (same_block) {
        wire_offset |= RAM_SAVE_FLAG_CONTINUE;
    }
    stq_be_p(be64_buf, wire_offset);
    g_byte_array_append(bpf_state.ring_batch, be64_buf, sizeof(be64_buf));

    if (!same_block) {
        uint8_t len = strlen(block->idstr);

        g_byte_array_append(bpf_state.ring_batch, &len, sizeof(len));
        g_byte_array_append(bpf_state.ring_batch,
                            (const uint8_t *)block->idstr, len);
        if (last_sent_block) {
            *last_sent_block = block;
        }
    }

    g_byte_array_append(bpf_state.ring_batch, data, TARGET_PAGE_SIZE);
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

    /* Queue page for batched write to the migration stream */
    bpf_fault_batch_append_page(block, offset, page_data);

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

    bpf_state.ring_batch = g_byte_array_sized_new(16 * TARGET_PAGE_SIZE);
    if (!bpf_state.ring_batch) {
        error_report("bpf_fault: failed to allocate ring batch buffer");
        ring_buffer__free(bpf_state.ringbuf);
        bpf_state.ringbuf = NULL;
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
    g_clear_pointer(&bpf_state.ring_batch, g_byte_array_unref);
    bpf_fault_snapshot_bpf__destroy(bpf_state.skel);
    bpf_state.skel = NULL;

    return -1;
}

void bpf_fault_wp_stop(void)
{
    RAMBlock *block;

    if (bpf_state.ringbuf) {
        ring_buffer__free(bpf_state.ringbuf);
        bpf_state.ringbuf = NULL;
    }
    g_clear_pointer(&bpf_state.ring_batch, g_byte_array_unref);

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

    bpf_state.current_last_sent_block = NULL;
}

int bpf_fault_poll_ring(QEMUFile *f, RAMBlock **last_sent_block)
{
    int ret;

    if (!bpf_state.ringbuf || !bpf_state.ring_batch) {
        return 0;
    }

    bpf_state.current_file = f;
    bpf_state.current_last_sent_block = last_sent_block;
    bpf_state.pages_written = 0;
    g_byte_array_set_size(bpf_state.ring_batch, 0);

    /* Non-blocking poll: timeout = 0 */
    ret = ring_buffer__poll(bpf_state.ringbuf, 0);
    if (bpf_state.ring_batch->len) {
        GByteArray *batch = bpf_state.ring_batch;
        gsize batch_len = batch->len;
        uint8_t *payload = g_byte_array_free(batch, false);

        bpf_state.ring_batch = g_byte_array_sized_new(batch_len);
        if (!bpf_state.ring_batch) {
            g_free(payload);
            bpf_state.current_file = NULL;
            bpf_state.current_last_sent_block = NULL;
            error_report("bpf_fault: failed to reallocate ring batch buffer");
            return -ENOMEM;
        }

        qemu_put_buffer_async(f, payload, batch_len, true);
    }

    if (ret < 0 && ret != -EINTR) {
        error_report("bpf_fault: ring buffer poll error: %s",
                     strerror(-ret));
    }

    bpf_state.current_file = NULL;
    bpf_state.current_last_sent_block = NULL;
    return (ret < 0 && ret != -EINTR) ? ret : bpf_state.pages_written;
}

bool bpf_fault_page_captured(RAMBlock *block, unsigned long page)
{
    BpfFaultBlockState *bs = find_block_state(block);

    if (!bs || page >= bs->num_pages) {
        return false;
    }

    return test_bit(page, bs->captured_bitmap);
}

int bpf_fault_release_protection(RAMBlock *block, unsigned long start_page,
                                  unsigned long npages)
{
    BpfFaultBlockState *bs;
    void *page_address;
    uint64_t run_length;
    int link_fd;

    if (!npages) {
        return 0;
    }

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
