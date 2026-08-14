# QEMU Snapshot Benchmark

QEMU counterpart of the Firecracker snapshot benchmark
(`firecracker/tests/bench/run_snapshot_bench.py`). Boots a guest from
the Firecracker CI artifact set (app rootfs with redis/memcached),
drives it with a host-side `memtier_benchmark --stats-interval=0.1`
process, takes one snapshot per configuration, and writes
`snapshot_benchmark_qemu_<workload>.json` plus `timeseries/qemu_*.csv`
in the shared `{config, results}` schema, so the bpf-fault plotting
scripts consume Firecracker and QEMU data interchangeably.

## Snapshot modes

| mode       | mechanism                                        |
|------------|--------------------------------------------------|
| `full`     | pause VM, migrate RAM+state to file, resume      |
| `migrate`  | stock live migration to file (dirty tracking)    |
| `live`     | background snapshot (userfaultfd write-protect)  |
| `live_bpf` | background snapshot with `x-bpf-fault-snapshot`  |

`migrate` is QEMU's baseline live snapshot: iterative pre-copy re-sends
every re-dirtied page, so a write-heavy guest can outrun it and the
migration never converges. The benchmark lifts the default 128 MiB/s
bandwidth cap (so non-convergence reflects the workload, not a
throttle), cancels after a 120 s timeout, and records
`results.converged = false` with the elapsed time and
`dirty_sync_count`. The background-snapshot modes copy each page exactly
once, so their total time is bounded by guest RAM size.

## Usage

```sh
./setup_experiment.sh          # deps, BPF skeleton, build, smoke test
sudo ./run_snapshot_bench.py --results-dir /path/to/results
```

Requires: the bpf-fault host kernel (BPF skeleton generation and the
`live_bpf` mode), KVM, `memtier_benchmark` with `--stats-interval`
(install_memtier.sh), and the Firecracker guest artifacts
(install_firecracker.sh). Root is needed for TAP networking.

Timing methodology: freeze windows come from QMP `STOP`/`RESUME` event
receipt times on the benchmark's monotonic clock — the same clock that
timestamps the memtier timeseries — so `ts_freeze_*`/`ts_snap_*` line
up with the CSVs exactly as in the Firecracker benchmark.
