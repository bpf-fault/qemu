// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_arena_common.h"

#define BLOCK_SIZE 4096

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef uint64_t Elf64_Addr;

typedef struct {
    Elf64_Addr *dst_addr;
    Elf64_Addr *src_addr;
    uint64_t copy_sz
} copy_entry;

// This acts as a queue of src and dst copies to be done
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(value, copy_entry);
	__uint(max_entries, 100);
} queue SEC(".maps");

// TODO: replace with page fault tracepoint.
SEC("lsm.s/file_open") // using lsm.s because it is a sleepable type
int BPF_PROG(fault_handler, struct file *file, int ret)
{
    copy_entry next_copy;

    bpf_printk("Fault Handler\n");

    // Pop next copy action from queue
    if (bpf_map_pop_elem(&queue, &next_copy) != 0)
        return -1;

    // Write into new userspace block
    if (bpf_probe_write_user(next_copy.dst_addr,
                             next_copy.src_addr,
                             next_copy.copy_sz) != 0)
        return -2;

    bpf_printk("%d\n", *(volatile int *) next_copy.dst_addr);

    return 0;
}
