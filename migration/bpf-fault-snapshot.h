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

#ifndef QEMU_MIGRATION_BPF_FAULT_SNAPSHOT_H
#define QEMU_MIGRATION_BPF_FAULT_SNAPSHOT_H

#include "exec/cpu-common.h"

/**
 * bpf_fault_snapshot_available: check if bpf_fault snapshot is supported
 *
 * Returns true if the kernel supports bpf_fault and libbpf is available.
 */
bool bpf_fault_snapshot_available(void);

/**
 * bpf_fault_wp_prepare: pre-load and verify the BPF program
 *
 * Opens and loads the BPF skeleton (including verifier pass). This is
 * the expensive part and should be called before the VM is paused to
 * minimize downtime.
 *
 * Returns 0 on success, negative value on error.
 */
int bpf_fault_wp_prepare(void);

/**
 * bpf_fault_wp_start: enable bpf_fault write-protection on all RAM blocks
 *
 * Attaches fault handlers for each RAM block and enables write protection.
 * The BPF program must already be loaded via bpf_fault_wp_prepare().
 * Must be called with BQL held, during the downtime window.
 *
 * Returns 0 on success, negative value on error.
 */
int bpf_fault_wp_start(void);

/**
 * bpf_fault_wp_stop: disable bpf_fault write-protection and clean up
 *
 * Frees ring buffer, clears block flags, and destroys BPF skeleton.
 */
void bpf_fault_wp_stop(void);

/**
 * bpf_fault_poll_ring: drain pending ring buffer entries and write pages
 *
 * Polls the BPF ring buffer for captured pages, writes them to the
 * migration stream, and marks them in the captured bitmap.
 *
 * @f: QEMUFile to write captured pages to
 *
 * Returns number of pages written, or negative on error.
 */
int bpf_fault_poll_ring(QEMUFile *f);

/**
 * bpf_fault_page_captured: check if a page was already captured via ring buffer
 *
 * @block: RAM block containing the page
 * @page: page index within the block
 *
 * Returns true if the page was already saved via the BPF ring buffer.
 */
bool bpf_fault_page_captured(RAMBlock *block, unsigned long page);

/**
 * bpf_fault_release_protection: remove write-protection from a page range
 *
 * @block: RAM block containing the range
 * @start_page: first page index in the range
 * @npages: number of pages to un-protect
 *
 * Returns 0 on success, negative value on error.
 */
int bpf_fault_release_protection(RAMBlock *block, unsigned long start_page,
                                  unsigned long npages);

#endif /* QEMU_MIGRATION_BPF_FAULT_SNAPSHOT_H */
