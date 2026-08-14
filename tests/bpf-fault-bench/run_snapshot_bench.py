#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the QEMU snapshot benchmark and write JSON results.

QEMU counterpart of Firecracker's tests/bench/run_snapshot_bench.py: for
each (workload, mode, mem size, iteration) it boots a fresh VM, runs a
guest application under load from a host-side memtier_benchmark process
(--stats-interval=0.1), takes one snapshot, and appends a
{config, results} record to snapshot_benchmark_qemu_<workload>.json in
--results-dir, with per-0.1s timeseries CSVs under timeseries/. The
schema matches the Firecracker benchmark so the bpf-fault plotting
scripts consume both.

Snapshot modes:
  full     - pause the VM, migrate RAM+state to a file, resume
  migrate  - dirty-tracking live migration to a file with the VM
             running (QEMU's stock live snapshot path). Under
             write-heavy load the dirty rate outpaces streaming and the
             migration never converges; a timeout records that outcome
             (results.converged = false).
  live     - background snapshot (userfaultfd write-protect)
  live_bpf - background snapshot with x-bpf-fault-snapshot=on

Guest artifacts (kernel, app rootfs, ssh key) are reused from the
Firecracker CI artifact set downloaded by install_firecracker.sh; pass
--artifacts-dir or set QEMU_BENCH_ARTIFACTS to override discovery.

Requires root (TAP networking) and the bpf-fault host kernel for
live_bpf. Configurations already present in the results file (with
their timeseries CSV intact) are skipped, so an interrupted sweep
resumes where it stopped.
"""

import argparse
import csv
import glob
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))

_DEFAULT_QEMU = os.path.join(_REPO_ROOT, "build", "qemu-system-x86_64")

# Artifact discovery: the Firecracker CI artifact set.
_FC_ARTIFACT_GLOB = os.path.join(
    _REPO_ROOT, "..", "firecracker", "build", "artifacts", "s3*", "x86_64")

GUEST_KERNEL = "bzImage-5.10.260"
GUEST_ROOTFS = "ubuntu-24.04-app.ext4"
GUEST_SSHKEY = "ubuntu-24.04-app.id_rsa"

TAP_NAME = "qbenchtap0"
HOST_IP = "192.168.241.1"
GUEST_IP = "192.168.241.2"

VCPU_COUNT = 2
# Fraction of guest RAM to pre-condition, as in the Firecracker
# benchmark (MEMORY_FILL_FRACTION). The guest's /tmp tmpfs is capped at
# size=50%, so the effective fill saturates there -- identically in
# both harnesses, since the write error is discarded in both.
MEMORY_FILL_FRACTION = 0.75
TIMESERIES_INTERVAL_S = 0.1
BASELINE_WINDOW_SEC = 5
POST_WINDOW_SEC = 5
BOOT_TIMEOUT_S = 90
MIGRATE_TIMEOUT_S = 120

# Workload parameters, identical to the Firecracker benchmark
# (tests/integration_tests/functional/experiment/constants.py) so
# cross-hypervisor numbers are comparable.
REDIS_WORKLOAD_PARAMS = {
    "redis_light": {"clients": 2,  "ops": "get",     "value_size": 128, "pipeline": 1},
    "redis_mixed": {"clients": 10, "ops": "set,get", "value_size": 128, "pipeline": 1},
    "redis_heavy": {"clients": 50, "ops": "set",     "value_size": 128, "pipeline": 1},
    # Saturating variant: pipelining removes the request-round-trip
    # ceiling, driving the server to capacity (see the Firecracker
    # benchmark's constants.py, kept in lockstep).
    "redis_sat":   {"clients": 50, "ops": "set",     "value_size": 128, "pipeline": 16},
}
MEMCACHED_WORKLOAD_PARAMS = {
    "memcached_light": {"clients": 2,  "ratio": "1:9"},
    "memcached_heavy": {"clients": 50, "ratio": "1:1"},
    "memcached_sat":   {"clients": 50, "ratio": "1:1", "pipeline": 16},
}

MODES = ["full", "migrate", "live", "live_bpf"]


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# QMP client (collects events with receipt wall-clock times)
# ---------------------------------------------------------------------------

class QMPClient:
    """Minimal QMP client.

    Events are retained in self.events with their QMP emission
    timestamps mapped onto the monotonic clock. Receipt times would be
    wrong for timing: events queue unread between commands and arrive
    in a burst with the next response."""

    def __init__(self, sock_path, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(sock_path)
                break
            except (ConnectionRefusedError, FileNotFoundError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        self.sockfile = self.sock.makefile("r")
        self.events = []
        # Map QMP event timestamps (CLOCK_REALTIME) onto the monotonic
        # clock the benchmark uses; drift over a run is negligible.
        self._rt_off = time.time() - time.monotonic()
        greeting = json.loads(self.sockfile.readline())
        assert "QMP" in greeting
        self._send({"execute": "qmp_capabilities"})
        resp = self._recv()
        assert "return" in resp, f"qmp_capabilities failed: {resp}"

    def _send(self, cmd):
        self.sock.sendall((json.dumps(cmd) + "\n").encode())

    def _recv(self):
        while True:
            line = self.sockfile.readline()
            if not line:
                raise ConnectionError("QMP connection closed")
            msg = json.loads(line)
            if "event" in msg:
                ts = msg.get("timestamp", {})
                mono = (ts.get("seconds", 0) + ts.get("microseconds", 0) / 1e6
                        - self._rt_off) if ts else time.monotonic()
                self.events.append((mono, msg))
                continue
            return msg

    def execute(self, command, **kwargs):
        cmd = {"execute": command}
        if kwargs:
            cmd["arguments"] = kwargs
        self._send(cmd)
        resp = self._recv()
        if "error" in resp:
            raise RuntimeError(f"QMP error ({command}): {resp['error']}")
        return resp.get("return", {})

    def drain_events(self):
        """Poll query-status purely to pull any queued events."""
        self.execute("query-status")

    def event_time(self, name, after=0.0):
        """Monotonic emission time of the first `name` event after `after`."""
        for t, ev in self.events:
            if ev.get("event") == name and t >= after:
                return t
        return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

def _get_cpu_seconds(pid):
    """Total CPU seconds (utime+stime) of the QEMU process so far."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return 0.0


def _setup_tap():
    subprocess.run(["ip", "link", "del", TAP_NAME],
                   stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["ip", "tuntap", "add", TAP_NAME, "mode", "tap"],
                   check=True)
    subprocess.run(["ip", "addr", "add", f"{HOST_IP}/30", "dev", TAP_NAME],
                   check=True)
    subprocess.run(["ip", "link", "set", TAP_NAME, "up"], check=True)


def _teardown_tap():
    subprocess.run(["ip", "link", "del", TAP_NAME],
                   stderr=subprocess.DEVNULL, check=False)


class QemuVM:
    """One QEMU guest: boot, ssh, QMP, teardown."""

    def __init__(self, qemu_bin, artifacts, mem_size_mib, workdir):
        self.workdir = workdir
        self.qmp_path = os.path.join(workdir, "qmp.sock")
        self.serial_path = os.path.join(workdir, "serial.log")
        self.sshkey = os.path.join(artifacts, GUEST_SSHKEY)
        kernel = os.path.join(artifacts, GUEST_KERNEL)
        rootfs = os.path.join(artifacts, GUEST_ROOTFS)

        _setup_tap()
        # ip=... uses the kernel's built-in IP autoconfig (IP_PNP), same
        # mechanism the Firecracker test framework uses for this rootfs.
        append = (
            "console=ttyS0 reboot=k panic=1 random.trust_cpu=on "
            "root=/dev/vda rw "
            f"ip={GUEST_IP}::{HOST_IP}:255.255.255.252::eth0:off"
        )
        cmd = [
            qemu_bin,
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-smp", str(VCPU_COUNT),
            "-m", f"{mem_size_mib}M",
            "-kernel", kernel,
            "-append", append,
            # -snapshot: guest writes go to a throwaway overlay, the
            # shared base rootfs is never dirtied.
            "-drive", f"file={rootfs},if=virtio,format=raw,cache=unsafe",
            "-snapshot",
            "-netdev", f"tap,id=n0,ifname={TAP_NAME},script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=n0",
            "-serial", f"file:{self.serial_path}",
            "-display", "none",
            "-qmp", f"unix:{self.qmp_path},server,nowait",
        ]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.qmp = QMPClient(self.qmp_path)

    @property
    def pid(self):
        return self.proc.pid

    def ssh(self, command, timeout=60):
        """Run a command in the guest; raises on nonzero exit."""
        cmd = [
            "ssh", "-i", self.sshkey,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR",
            f"root@{GUEST_IP}", command,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        if res.returncode != 0:
            raise RuntimeError(
                f"guest command failed ({res.returncode}): {command}\n"
                f"stderr: {res.stderr.strip()}")
        return res.stdout

    def wait_for_boot(self):
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited during boot (rc={self.proc.returncode}); "
                    f"see {self.serial_path}")
            try:
                self.ssh("true", timeout=8)
                return
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(1)
        raise RuntimeError(f"guest did not boot within {BOOT_TIMEOUT_S}s")

    def kill(self):
        try:
            self.qmp.execute("quit")
        except (RuntimeError, ConnectionError, OSError):
            pass
        self.qmp.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        _teardown_tap()


# ---------------------------------------------------------------------------
# Guest workload setup (mirrors the Firecracker experiment helpers)
# ---------------------------------------------------------------------------

def _setup_redis(vm, mem_size_mib, value_size=128):
    redis_maxmem = mem_size_mib // 2
    vm.ssh("systemctl stop redis-server redis 2>/dev/null || "
           "redis-cli shutdown nosave 2>/dev/null || true; sleep 0.3")
    vm.ssh(f"redis-server --daemonize yes "
           f"--maxmemory {redis_maxmem}mb "
           f"--maxmemory-policy allkeys-lru "
           f"--save '' --appendonly no "
           f"--bind 0.0.0.0 --protected-mode no")
    vm.ssh("for i in $(seq 1 30); do "
           "  redis-cli ping | grep -q PONG && break; sleep 0.2; done",
           timeout=15)
    prefill_ops = redis_maxmem * 1024
    vm.ssh(f"redis-benchmark -t set -n {prefill_ops} -d {value_size} "
           f"-r 1000000 -P 16 -q", timeout=180)


def _setup_memcached(vm, mem_size_mib):
    memcached_mem = mem_size_mib // 2
    vm.ssh("systemctl stop memcached 2>/dev/null || true; "
           "pkill -x memcached 2>/dev/null || true; sleep 0.3")
    vm.ssh(f"setsid /usr/bin/memcached -m {memcached_mem} -t 2 -p 11211 "
           f"-l 0.0.0.0 -u root </dev/null >/tmp/memcached.log 2>&1 &")
    vm.ssh("for i in $(seq 1 50); do "
           "  nc -z 127.0.0.1 11211 2>/dev/null && break; sleep 0.2; done; "
           "nc -z 127.0.0.1 11211", timeout=20)
    # Single pipelined pass over every key, same as the Firecracker
    # benchmark, so the dataset is identical across hypervisors.
    vm.ssh("memtier_benchmark -s 127.0.0.1 -p 11211 "
           "--protocol=memcache_text --key-maximum=500000 --data-size=512 "
           "-c 10 -t 2 --ratio=1:0 -n allkeys --hide-histogram "
           "--key-pattern=P:P --pipeline=16", timeout=180)


def _condition_memory(vm, mem_size_mib):
    """Populate MEMORY_FILL_FRACTION of guest RAM with urandom data,
    mirroring the Firecracker benchmark's pre-conditioning so snapshot
    streaming covers comparably populated memory."""
    prefill_mib = max(int(mem_size_mib * MEMORY_FILL_FRACTION), 16)
    vm.ssh(f"head -c {prefill_mib}M /dev/urandom > /tmp/prefill "
           f"2>/dev/null; sync", timeout=180)


def _workload_protocol_params(workload):
    if workload.startswith("redis"):
        return "redis", REDIS_WORKLOAD_PARAMS[workload]
    return "memcache_text", MEMCACHED_WORKLOAD_PARAMS[workload]


# ---------------------------------------------------------------------------
# Host-side memtier timeseries (ported from the Firecracker benchmark,
# minus netns: the TAP device lives in the host namespace)
# ---------------------------------------------------------------------------

def _ratio_str(params):
    if "ratio" in params:
        return params["ratio"]
    ops = params.get("ops", "get").lower()
    return {"set": "1:0", "get": "0:1"}.get(ops, "1:1")


def _start_memtier(protocol, params, duration_sec):
    tmp_dir = tempfile.mkdtemp(prefix="ts_memtier_")
    json_path = os.path.join(tmp_dir, "ts.json")
    cmd = [
        "memtier_benchmark",
        "--server", GUEST_IP,
        "--port", "6379" if protocol == "redis" else "11211",
        "--protocol", protocol,
        "--threads", "1",
        "--clients", str(params["clients"]),
        "--pipeline", str(params.get("pipeline", 1)),
        "--ratio", _ratio_str(params),
        "--data-size", str(params.get("value_size", 128)),
        "--test-time", str(int(duration_sec)),
        "--stats-interval", str(TIMESERIES_INTERVAL_S),
        "--json-out-file", json_path,
        "--hide-histogram",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return {"proc": proc, "json_path": json_path, "tmp_dir": tmp_dir,
            "start_wall": time.monotonic()}


def _stop_memtier(handle):
    proc = handle["proc"]
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except OSError:
        pass


def _write_timeseries_csv(handle, results_dir, workload, mem_size_mib,
                          mode, iteration):
    """Write memtier Time-Serie buckets to timeseries/qemu_<...>.csv in
    the results store; returns the relative path."""
    json_path = handle["json_path"]
    tmp_dir = handle["tmp_dir"]
    try:
        with open(json_path) as f:
            data = json.load(f)
        totals = data.get("ALL STATS", {}).get("Totals", {})
        time_serie = totals.get("Time-Serie") or {}
        runtime = data.get("ALL STATS", {}).get("Runtime", {})
        total_ms = runtime.get("Total duration")
        duration_sec = float(total_ms) / 1000.0 if total_ms else None

        buckets = []
        for key in sorted(time_serie, key=lambda k: float(k)):
            bucket = time_serie[key]
            t_rel_s = float(key)
            if duration_sec is not None:
                bucket_dur = max(0.0, min(
                    TIMESERIES_INTERVAL_S,
                    duration_sec - (t_rel_s - TIMESERIES_INTERVAL_S)))
            else:
                bucket_dur = TIMESERIES_INTERVAL_S
            if bucket_dur <= 0:
                continue
            count = float(bucket.get("Count") or 0)
            buckets.append((
                t_rel_s,
                count / bucket_dur,
                float(bucket.get("Average Latency") or 0),
                float(bucket.get("p50.00") or 0),
                float(bucket.get("p99.00") or 0),
                float(bucket.get("p99.90") or 0),
            ))
    except Exception:  # noqa: BLE001
        buckets = []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Fill gaps (paused VM -> no bucket emitted) with explicit zero rows.
    filled = []
    for i, entry in enumerate(buckets):
        if i > 0:
            t_next = round(buckets[i - 1][0] + TIMESERIES_INTERVAL_S, 3)
            while t_next < entry[0] - TIMESERIES_INTERVAL_S * 0.5:
                filled.append((t_next, 0.0, 0.0, 0.0, 0.0, 0.0))
                t_next = round(t_next + TIMESERIES_INTERVAL_S, 3)
        filled.append(entry)

    ts_dir = os.path.join(results_dir, "timeseries")
    os.makedirs(ts_dir, exist_ok=True)
    name = f"qemu_{workload}_{mem_size_mib}mib_{mode}_iter{iteration:02d}.csv"
    with open(os.path.join(ts_dir, name), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_ms", "t_rel_s", "throughput", "avg_ms",
                    "p50_ms", "p99_ms", "p999_ms", "failed"])
        for t_rel_s, tput, avg_ms, p50_ms, p99_ms, p999_ms in filled:
            w.writerow([round(t_rel_s * 1000, 1), round(t_rel_s, 3),
                        round(tput, 1), round(avg_ms, 3), round(p50_ms, 3),
                        round(p99_ms, 3), round(p999_ms, 3), 0])
    return f"timeseries/{name}"


def _compute_window_stats(ts_path, t_start, t_end):
    """Freeze-to-completion window stats; identical to the Firecracker
    benchmark so freeze_window fields agree across hypervisors."""
    empty = {
        "throughput_ops_s": 0.0, "avg_latency_us": 0.0, "p99_us": 0.0,
        "p999_us": 0.0, "max_avg_latency_us": 0.0, "max_p999_us": 0.0,
        "sample_count": 0,
    }
    if not ts_path or not os.path.exists(ts_path) or t_end <= t_start:
        return empty
    rows = []
    with open(ts_path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                t = float(row["t_rel_s"])
                if t < t_start or t > t_end or int(row.get("failed") or 0):
                    continue
                rows.append({
                    "thr": float(row["throughput"]),
                    "avg": float(row.get("avg_ms", 0) or 0),
                    "p99": float(row.get("p99_ms", 0) or 0),
                    "p999": float(row.get("p999_ms", 0) or 0),
                })
            except (KeyError, ValueError):
                pass
    if not rows:
        return empty
    n = len(rows)
    avg = [r["avg"] for r in rows]
    p999 = [r["p999"] for r in rows]
    return {
        "throughput_ops_s": sum(r["thr"] for r in rows) / n,
        "avg_latency_us": sum(avg) / n * 1000,
        "p99_us": sum(r["p99"] for r in rows) / n * 1000,
        "p999_us": sum(p999) / n * 1000,
        "max_avg_latency_us": max(avg) * 1000,
        "max_p999_us": max(p999) * 1000,
        "sample_count": n,
    }


# ---------------------------------------------------------------------------
# Snapshot triggers
# ---------------------------------------------------------------------------

def _wait_migration(qmp, timeout_s):
    """Poll query-migrate until completed/failed or timeout.
    Returns (state, last_status_dict)."""
    deadline = time.monotonic() + timeout_s
    status = {}
    while time.monotonic() < deadline:
        time.sleep(0.1)
        status = qmp.execute("query-migrate")
        state = status.get("status", "unknown")
        if state in ("completed", "failed", "cancelled"):
            return state, status
    return "timeout", status


def _snapshot_file(workdir):
    return os.path.join(workdir, "snap.mem")


def _uncap_bandwidth(qmp):
    """Lift QEMU's default 128 MiB/s migration throttle. It applies to
    every mode (it would serialize a paused full snapshot and the live
    modes' stream phase alike), so snapshots run at device speed and
    non-convergence of the migrate mode reflects the workload."""
    qmp.execute("migrate-set-parameters", **{"max-bandwidth": 100 * 10**9})


def _do_full_snapshot(vm, t0_ref):
    """Pause -> migrate-to-file -> resume. Returns timing dict."""
    qmp = vm.qmp
    path = _snapshot_file(vm.workdir)
    _uncap_bandwidth(qmp)
    t_start = time.monotonic()
    qmp.execute("stop")
    qmp.execute("migrate", uri=f"file:{path}")
    state, _ = _wait_migration(qmp, MIGRATE_TIMEOUT_S)
    if state != "completed":
        raise RuntimeError(f"full snapshot migration state: {state}")
    qmp.execute("cont")
    t_end = time.monotonic()
    total_ms = (t_end - t_start) * 1000
    return {
        "mode": "full", "converged": True,
        "total_ms": total_ms, "downtime_ms": total_ms,
        "phases_us": {"create": total_ms * 1000},
        "freeze_start_s": t_start - t0_ref, "freeze_end_s": t_end - t0_ref,
        "snap_start_s": t_start - t0_ref, "snap_end_s": t_end - t0_ref,
        "snapshot_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
    }


def _do_migrate_snapshot(vm, t0_ref):
    """Dirty-tracking live migration to a file with the VM running.

    QEMU's stock non-WP path: iterative pre-copy re-sends re-dirtied
    pages, so a write-heavy guest can outrun it indefinitely. On timeout
    the migration is cancelled and converged=false recorded."""
    qmp = vm.qmp
    path = _snapshot_file(vm.workdir)
    _uncap_bandwidth(qmp)
    t_start = time.monotonic()
    qmp.execute("migrate", uri=f"file:{path}")
    state, status = _wait_migration(qmp, MIGRATE_TIMEOUT_S)
    converged = state == "completed"
    if not converged:
        try:
            qmp.execute("migrate_cancel")
        except RuntimeError:
            pass
        # Wait out the cancellation so teardown is clean.
        _wait_migration(qmp, 15)
    t_end = time.monotonic()
    qmp.drain_events()
    # Downtime = the final stop-copy window (STOP -> completion).
    stop_t = qmp.event_time("STOP", after=t_start)
    downtime_ms = (t_end - stop_t) * 1000 if (converged and stop_t) else 0.0
    ram = status.get("ram", {})
    return {
        "mode": "migrate", "converged": converged,
        "total_ms": (t_end - t_start) * 1000, "downtime_ms": downtime_ms,
        "phases_us": {"stream": (t_end - t_start) * 1e6},
        "freeze_start_s": (stop_t - t0_ref) if stop_t else (t_end - t0_ref),
        "freeze_end_s": t_end - t0_ref,
        "snap_start_s": t_start - t0_ref, "snap_end_s": t_end - t0_ref,
        "dirty_sync_count": ram.get("dirty-sync-count", 0),
        "ram_transferred": ram.get("transferred", 0),
        "snapshot_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
    }


def _do_background_snapshot(vm, t0_ref, bpf):
    """Background snapshot (uffd-wp, or bpf_fault when bpf=True)."""
    qmp = vm.qmp
    path = _snapshot_file(vm.workdir)
    qmp.execute("migrate-set-capabilities", capabilities=[
        {"capability": "background-snapshot", "state": True}])
    if bpf:
        qmp.execute("migrate-set-parameters",
                    **{"x-bpf-fault-snapshot": True})
    _uncap_bandwidth(qmp)
    t_start = time.monotonic()
    qmp.execute("migrate", uri=f"file:{path}")
    state, status = _wait_migration(qmp, MIGRATE_TIMEOUT_S)
    if state != "completed":
        raise RuntimeError(f"background snapshot state: {state} "
                           f"(bpf={bpf}): {status}")
    t_end = time.monotonic()
    qmp.drain_events()
    # Freeze window: the VM is stopped while vmstate is saved and WP is
    # armed, then resumed for streaming.
    stop_t = qmp.event_time("STOP", after=t_start) or t_start
    resume_t = qmp.event_time("RESUME", after=stop_t) or t_end
    freeze_ms = (resume_t - stop_t) * 1000
    return {
        "mode": "live_bpf" if bpf else "live", "converged": True,
        "total_ms": (t_end - t_start) * 1000, "downtime_ms": freeze_ms,
        "phases_us": {
            "phase1": (stop_t - t_start) * 1e6,
            "freeze": freeze_ms * 1000,
            "stream": (t_end - resume_t) * 1e6,
            "finalize": 0.0,
        },
        "freeze_start_s": stop_t - t0_ref, "freeze_end_s": resume_t - t0_ref,
        "snap_start_s": t_start - t0_ref, "snap_end_s": t_end - t0_ref,
        "snapshot_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
    }


_MODE_RUNNERS = {
    "full": lambda vm, t0: _do_full_snapshot(vm, t0),
    "migrate": lambda vm, t0: _do_migrate_snapshot(vm, t0),
    "live": lambda vm, t0: _do_background_snapshot(vm, t0, bpf=False),
    "live_bpf": lambda vm, t0: _do_background_snapshot(vm, t0, bpf=True),
}


# ---------------------------------------------------------------------------
# Results store ({config, results} records, checkpointed)
# ---------------------------------------------------------------------------

def results_path(results_dir, workload):
    return os.path.join(results_dir, f"snapshot_benchmark_qemu_{workload}.json")


def load_records(results_dir, workload):
    path = results_path(results_dir, workload)
    if not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        log(f"warning: could not read {path}; starting fresh")
        return []


def checkpoint_records(results_dir, workload, records):
    records.sort(key=lambda r: (
        r["config"]["mode"], r["config"]["mem_size_mib"],
        r["config"]["iteration"]))
    path = results_path(results_dir, workload)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(records, f, indent=4)
    os.replace(tmp, path)


def config_done(records, results_dir, mode, mem, iteration):
    for r in records:
        c = r["config"]
        if (c.get("mode"), c.get("mem_size_mib"), c.get("iteration")) != \
                (mode, mem, iteration):
            continue
        ts = r.get("results", {}).get("timeseries_file") or ""
        if ts and not os.path.isfile(os.path.join(results_dir, ts)):
            return False
        return True
    return False


# ---------------------------------------------------------------------------
# One configuration
# ---------------------------------------------------------------------------

def run_config(qemu_bin, artifacts, results_dir, workload, mode, mem,
               iteration, scratch_dir=None):
    # Snapshot files are guest-RAM sized; keep them off the root disk.
    workdir = tempfile.mkdtemp(prefix="qemu_snap_", dir=scratch_dir)
    vm = QemuVM(qemu_bin, artifacts, mem, workdir)
    try:
        vm.wait_for_boot()
        _condition_memory(vm, mem)
        protocol, params = _workload_protocol_params(workload)
        if protocol == "redis":
            _setup_redis(vm, mem, value_size=params.get("value_size", 128))
        else:
            _setup_memcached(vm, mem)

        duration = BASELINE_WINDOW_SEC + MIGRATE_TIMEOUT_S + POST_WINDOW_SEC
        ts = _start_memtier(protocol, params, duration)
        cpu_baseline_start = _get_cpu_seconds(vm.pid)
        time.sleep(BASELINE_WINDOW_SEC)
        cpu_snap_start = _get_cpu_seconds(vm.pid)

        timing = _MODE_RUNNERS[mode](vm, ts["start_wall"])
        cpu_snap_end = _get_cpu_seconds(vm.pid)

        time.sleep(POST_WINDOW_SEC)
        _stop_memtier(ts)

        ts_rel = _write_timeseries_csv(ts, results_dir, workload, mem,
                                       mode, iteration)
        freeze_window = _compute_window_stats(
            os.path.join(results_dir, ts_rel),
            timing["freeze_start_s"], timing["snap_end_s"])

        snap_wall = timing["snap_end_s"] - timing["snap_start_s"]
        results = {
            "cpu": {
                "baseline_cpu_s": round(cpu_snap_start - cpu_baseline_start, 3),
                "during_cpu_s": round(cpu_snap_end - cpu_snap_start, 3),
                "baseline_util": round(
                    (cpu_snap_start - cpu_baseline_start)
                    / BASELINE_WINDOW_SEC, 3),
                "during_util": round(
                    (cpu_snap_end - cpu_snap_start) / snap_wall, 3)
                    if snap_wall > 0 else 0.0,
            },
            "total_snapshot_ms": round(timing["total_ms"], 3),
            "downtime_ms": round(timing["downtime_ms"], 3),
            "converged": timing["converged"],
            "phase_breakdown_us": {k: round(v, 1)
                                   for k, v in timing["phases_us"].items()},
            "freeze_window": {
                k: (int(v) if k == "sample_count" else round(v, 3))
                for k, v in freeze_window.items()
            },
            "snapshot_bytes": timing.get("snapshot_bytes", 0),
            "timeseries_file": ts_rel,
            "ts_snap_start_s": round(timing["snap_start_s"], 3),
            "ts_snap_end_s": round(timing["snap_end_s"], 3),
            "ts_freeze_start_s": round(timing["freeze_start_s"], 3),
            "ts_freeze_end_s": round(timing["freeze_end_s"], 3),
        }
        for extra in ("dirty_sync_count", "ram_transferred"):
            if extra in timing:
                results[extra] = timing[extra]

        return {
            "config": {
                "name": "qemu_snapshot",
                "workload": workload,
                "mem_size_mib": mem,
                "mode": mode,
                "iteration": iteration,
            },
            "results": results,
        }
    finally:
        vm.kill()
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_artifacts(override):
    for candidate in filter(None, [
            override, os.environ.get("QEMU_BENCH_ARTIFACTS")]):
        if os.path.isfile(os.path.join(candidate, GUEST_ROOTFS)):
            return candidate
        log(f"ERROR: {GUEST_ROOTFS} not found in {candidate}")
        sys.exit(1)
    for candidate in sorted(glob.glob(_FC_ARTIFACT_GLOB)):
        if os.path.isfile(os.path.join(candidate, GUEST_ROOTFS)):
            return candidate
    log("ERROR: no guest artifacts found; run install_firecracker.sh "
        "or pass --artifacts-dir")
    sys.exit(1)


def main():
    global MIGRATE_TIMEOUT_S

    ap = argparse.ArgumentParser(
        description="Run the QEMU snapshot benchmark.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--workloads", nargs="+",
                    default=["redis_heavy", "memcached_heavy"])
    ap.add_argument("--modes", nargs="+", default=MODES,
                    choices=MODES)
    ap.add_argument("--mem-sizes", type=int, nargs="+",
                    default=[4096, 8192], metavar="MiB")
    ap.add_argument("--iterations", type=int, default=3)
    ap.add_argument("--results-dir", required=True,
                    help="Results store (JSON + timeseries/)")
    ap.add_argument("--qemu", default=_DEFAULT_QEMU,
                    help="qemu-system-x86_64 binary")
    ap.add_argument("--artifacts-dir", default=None,
                    help="Guest kernel/rootfs/key directory")
    ap.add_argument("--scratch-dir", default=None,
                    help="Directory for guest-RAM-sized snapshot scratch "
                         "files (default: system temp dir)")
    ap.add_argument("--migrate-timeout", type=int, default=MIGRATE_TIMEOUT_S,
                    metavar="SEC",
                    help="Non-convergence timeout for the migrate mode")
    ap.add_argument("--no-reuse-results", action="store_true")
    args = ap.parse_args()

    MIGRATE_TIMEOUT_S = args.migrate_timeout
    if args.scratch_dir:
        os.makedirs(args.scratch_dir, exist_ok=True)

    if os.geteuid() != 0:
        log("ERROR: must run as root (TAP networking)")
        sys.exit(1)
    if not os.path.isfile(args.qemu):
        log(f"ERROR: qemu binary not found: {args.qemu}")
        sys.exit(1)
    artifacts = find_artifacts(args.artifacts_dir)
    log(f"Guest artifacts: {artifacts}")
    os.makedirs(args.results_dir, exist_ok=True)

    for workload in args.workloads:
        records = [] if args.no_reuse_results \
            else load_records(args.results_dir, workload)
        for mode in args.modes:
            for mem in args.mem_sizes:
                for iteration in range(args.iterations):
                    if config_done(records, args.results_dir, mode, mem,
                                   iteration):
                        log(f"Skipping {workload} {mode} mem={mem} "
                            f"iteration={iteration} (already in results)")
                        continue
                    log(f"Running config: {workload} {mode} mem={mem} "
                        f"iteration={iteration}")
                    rec = run_config(args.qemu, artifacts, args.results_dir,
                                     workload, mode, mem, iteration,
                                     scratch_dir=args.scratch_dir)
                    records = [r for r in records
                               if (r["config"]["mode"],
                                   r["config"]["mem_size_mib"],
                                   r["config"]["iteration"])
                               != (mode, mem, iteration)]
                    records.append(rec)
                    checkpoint_records(args.results_dir, workload, records)
                    res = rec["results"]
                    log(f"  -> total={res['total_snapshot_ms']:.0f}ms "
                        f"downtime={res['downtime_ms']:.0f}ms "
                        f"converged={res['converged']}")
        log(f"{workload}: {len(records)} records in "
            f"{results_path(args.results_dir, workload)}")


if __name__ == "__main__":
    main()
