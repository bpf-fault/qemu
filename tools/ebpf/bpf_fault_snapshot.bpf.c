/*
 * eBPF bpf_fault snapshot program
 *
 * Uses bpf_fault kernel interface to capture page content on write-protect
 * faults via a BPF ring buffer, avoiding the blocking IPC overhead of
 * userfaultfd.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Build bpf_fault_snapshot.bpf.skeleton.h:
 * make -f Makefile.ebpf clean all
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PAGE_SIZE 4096

struct ring_buf_entry {
    __u64 address;
    __u8 data[PAGE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024); /* 256 MB */
} ring_buf SEC(".maps");

/*
 * handle_wp_fault - called by bpf_fault on write-protect faults
 *
 * Captures the pre-write page content into the ring buffer and returns 0
 * to allow the write to proceed immediately (non-blocking).
 */
SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx,
             unsigned char *buf)
{
    struct ring_buf_entry *entry;
    volatile unsigned char *src = (volatile unsigned char *)buf;

    if (!buf)
        return 0;

    entry = bpf_ringbuf_reserve(&ring_buf, sizeof(*entry), 0);
    if (!entry) {
        return 0; /* drop on ring buffer full, page will be re-dirtied */
    }

    entry->address = ops_ctx->address;
    for (int i = 0; i < PAGE_SIZE; i++)
        entry->data[i] = src[i];
    bpf_ringbuf_submit(entry, 0);

    return 0;
}

SEC(".struct_ops.link")
struct fault_ops snapshot_fault_ops = {
    .handle_wp_fault = (void *)handle_wp_fault,
};

char _license[] SEC("license") = "GPL";
