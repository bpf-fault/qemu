/*
 * bpf_fault-based background snapshot stub
 *
 * Used when QEMU is built without libbpf support.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "bpf-fault-snapshot.h"

bool bpf_fault_snapshot_available(void)
{
    return false;
}

int bpf_fault_wp_prepare(void)
{
    g_assert_not_reached();
}

int bpf_fault_wp_start(void)
{
    g_assert_not_reached();
}

void bpf_fault_wp_stop(void)
{
    g_assert_not_reached();
}

int bpf_fault_poll_ring(QEMUFile *f)
{
    g_assert_not_reached();
}

bool bpf_fault_page_captured(RAMBlock *block, unsigned long page)
{
    return false;
}

int bpf_fault_release_protection(RAMBlock *block, unsigned long start_page,
                                  unsigned long npages)
{
    g_assert_not_reached();
}
