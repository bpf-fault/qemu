#!/usr/bin/env python3
"""
Benchmark for QEMU background snapshot (UFFD-WP) via QMP.

Connects to a running QEMU instance, enables x-background-snapshot,
triggers a migration to /dev/null, and reports timing.

Usage:
    bench-bg-snapshot-qmp.py <qmp-socket> [--serial-file <path>] [--settle <secs>]

    --serial-file: path to serial output file; wait for guest 'B' output
                   before snapshotting (confirms guest is actively writing)
    --settle:      seconds to let guest run before triggering snapshot (default: 2)
"""

import json
import os
import socket
import sys
import time


class QMPClient:
    def __init__(self, sock_path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock_path)
        self.sockfile = self.sock.makefile('r')
        greeting = json.loads(self.sockfile.readline())
        assert 'QMP' in greeting
        self._send({'execute': 'qmp_capabilities'})
        resp = self._recv()
        assert 'return' in resp, f"qmp_capabilities failed: {resp}"

    def _send(self, cmd):
        self.sock.sendall((json.dumps(cmd) + '\n').encode())

    def _recv(self):
        while True:
            line = self.sockfile.readline()
            if not line:
                raise ConnectionError("QMP connection closed")
            msg = json.loads(line)
            if 'event' in msg:
                continue
            return msg

    def execute(self, command, **kwargs):
        cmd = {'execute': command}
        if kwargs:
            cmd['arguments'] = kwargs
        self._send(cmd)
        resp = self._recv()
        if 'error' in resp:
            raise RuntimeError(f"QMP error: {resp['error']}")
        return resp.get('return', {})

    def close(self):
        self.sock.close()


def wait_for_serial(serial_file, timeout=30):
    """Wait for the guest to output 'B' on serial, indicating it's in
    the main write loop (has finished zeroing and is actively dirtying pages)."""
    print(f"Waiting for guest write activity (serial 'B' in {serial_file})...")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if os.path.exists(serial_file):
                with open(serial_file, 'r') as f:
                    data = f.read()
                if 'B' in data:
                    print(f"  Guest is actively writing ({len(data)} bytes of serial output)")
                    return True
        except (IOError, OSError):
            pass
        time.sleep(0.1)
    print("WARNING: Timed out waiting for guest serial output")
    return False


def main():
    args = sys.argv[1:]
    if not args:
        print(f"Usage: {sys.argv[0]} <qmp-socket> [--serial-file <path>] [--settle <secs>]")
        sys.exit(1)

    sock_path = args[0]
    serial_file = None
    settle_secs = 2.0

    i = 1
    while i < len(args):
        if args[i] == '--serial-file' and i + 1 < len(args):
            serial_file = args[i + 1]
            i += 2
        elif args[i] == '--settle' and i + 1 < len(args):
            settle_secs = float(args[i + 1])
            i += 2
        else:
            i += 1

    print("Connecting to QMP...")
    qmp = QMPClient(sock_path)

    print("Enabling x-background-snapshot capability...")
    qmp.execute('migrate-set-capabilities',
                capabilities=[{
                    'capability': 'background-snapshot',
                    'state': True
                }])

    print("Starting VM (cont)...")
    qmp.execute('cont')

    if serial_file:
        wait_for_serial(serial_file)
        print(f"Letting guest dirty pages for {settle_secs}s before snapshot...")
        time.sleep(settle_secs)
    else:
        time.sleep(0.5)

    print("Starting background snapshot migration to /dev/null...")
    t_start = time.monotonic()
    qmp.execute('migrate', uri='exec:cat > /dev/null')

    while True:
        time.sleep(0.2)
        status = qmp.execute('query-migrate')
        state = status.get('status', 'unknown')

        if state == 'completed':
            t_end = time.monotonic()
            wall_time_ms = (t_end - t_start) * 1000

            setup_time = status.get('setup-time', 0)
            total_time = status.get('total-time', 0)
            ram_info = status.get('ram', {})
            transferred = ram_info.get('transferred', 0)
            total_ram = ram_info.get('total', 0)
            pages_per_sec = ram_info.get('pages-per-second', 0)
            mbps = ram_info.get('mbps', 0)
            normal_pages = ram_info.get('normal', 0)
            zero_pages = ram_info.get('duplicate', 0)

            print("\n=== Background Snapshot Benchmark Results ===")
            print(f"  Status:          {state}")
            print(f"  Setup time:      {setup_time} ms  (includes page population)")
            print(f"  Total time:      {total_time} ms  (QEMU-reported)")
            print(f"  Wall time:       {wall_time_ms:.1f} ms")
            print(f"  RAM total:       {total_ram / (1024*1024):.1f} MB")
            print(f"  RAM transferred: {transferred / (1024*1024):.1f} MB")
            print(f"  Normal pages:    {normal_pages}")
            print(f"  Zero pages:      {zero_pages}")
            print(f"  Pages/sec:       {pages_per_sec}")
            print(f"  Throughput:      {mbps:.1f} Mbps")
            print("==============================================\n")
            break

        elif state == 'failed':
            print(f"Migration FAILED: {status}")
            break

        elif state in ('active', 'setup'):
            pass
        else:
            print(f"  status: {state}")

    qmp.execute('quit')
    qmp.close()


if __name__ == '__main__':
    main()
