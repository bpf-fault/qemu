#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build QEMU with bpf_fault snapshot support and prepare the benchmark.
#
# Phases (each announced on stdout for the caller's progress filter):
#   1. Install build dependencies
#   2. Generate the BPF skeleton (needs bpftool + the bpf-fault kernel's BTF)
#   3. Configure and build qemu-system-x86_64
#   4. Verify guest artifacts (reused from the Firecracker artifact set)
#   5. Smoke test: synthetic background-snapshot benchmark
#
# Flags: --skip-deps --skip-build --no-smoke-test
set -eu -o pipefail

SCRIPT_PATH=$(realpath "$0")
REPO_ROOT=$(realpath "$(dirname "$SCRIPT_PATH")/../..")
BUILD_DIR="$REPO_ROOT/build"

SKIP_DEPS=0
SKIP_BUILD=0
SMOKE_TEST=1
for arg in "$@"; do
	case "$arg" in
	--skip-deps) SKIP_DEPS=1 ;;
	--skip-build) SKIP_BUILD=1 ;;
	--no-smoke-test) SMOKE_TEST=0 ;;
	*) echo "unknown flag: $arg" >&2; exit 1 ;;
	esac
done

if [ "$SKIP_DEPS" = 1 ]; then
	echo "Skipping build dependencies"
else
	echo "Installing build dependencies"
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
		ninja-build libglib2.0-dev libpixman-1-dev libslirp-dev \
		libcap-ng-dev libattr1-dev flex bison \
		python3-venv > /dev/null
fi

if [ -s "$REPO_ROOT/migration/bpf_fault_snapshot.bpf.skeleton.h" ] \
		&& [ "$SKIP_BUILD" = 1 ]; then
	echo "Skipping BPF skeleton generation"
else
	echo "Generating BPF skeleton"
	if [ ! -e /sys/kernel/btf/vmlinux ]; then
		echo "error: /sys/kernel/btf/vmlinux missing; boot the bpf-fault kernel" >&2
		exit 1
	fi
	make -C "$REPO_ROOT/tools/ebpf" -f Makefile.ebpf \
		bpf_fault_snapshot.bpf.skeleton.h
fi

if [ "$SKIP_BUILD" = 1 ] && [ -x "$BUILD_DIR/qemu-system-x86_64" ]; then
	echo "Skipping QEMU build"
else
	echo "Building QEMU (x86_64-softmmu)"
	# Fresh checkouts leave meson_options.txt newer than the committed
	# (generated) meson-buildoptions.sh, which triggers a maintainer
	# regeneration rule that introspects the full meson environment --
	# including a rustc lookup that --disable-rust does not suppress.
	# The committed file is current; refresh its timestamp instead.
	touch "$REPO_ROOT/scripts/meson-buildoptions.sh"
	# bpf_fault needs the bpf-fault kernel's libbpf (installed to
	# /usr/local by install_kernel.sh), not the distro libbpf-dev:
	# only the fork has bpf_map__attach_fault_ops. PKG_CONFIG_PATH
	# entries are searched first, so the fork wins even if a distro
	# libbpf is installed.
	export PKG_CONFIG_PATH="/usr/local/lib64/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
	if ! pkg-config --atleast-version=1.7 libbpf; then
		echo "error: bpf-fault libbpf not found; run install_kernel.sh first" >&2
		exit 1
	fi
	mkdir -p "$BUILD_DIR"
	cd "$BUILD_DIR"
	if [ ! -f config-host.mak ]; then
		../configure --target-list=x86_64-softmmu \
			--enable-kvm --enable-slirp --enable-bpf \
			--disable-rust --disable-docs > configure.log
	fi
	make -j"$(nproc)" qemu-system-x86_64 > build.log 2>&1
	cd "$REPO_ROOT"
fi

echo "Verifying bpf_fault support in the built binary"
# Feed a QMP session that exits: with bare stdin EOF, -qmp stdio would
# leave QEMU running and this check would hang.
if ! printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}' \
		| timeout 15 "$BUILD_DIR/qemu-system-x86_64" -M none -qmp stdio \
		| grep -q '"QMP"'; then
	echo "error: built qemu-system-x86_64 does not start" >&2
	exit 1
fi

echo "Checking guest artifacts"
ARTIFACTS=$(ls -d "$REPO_ROOT"/../firecracker/build/artifacts/s3*/x86_64 \
	2> /dev/null | head -1 || true)
if [ -z "$ARTIFACTS" ] \
		|| [ ! -f "$ARTIFACTS/ubuntu-24.04-app.ext4" ]; then
	echo "error: Firecracker guest artifacts not found; run install_firecracker.sh first" >&2
	exit 1
fi
echo "  using $ARTIFACTS"

if [ "$SMOKE_TEST" = 1 ]; then
	echo "Running synthetic smoke test"
	# bench-bg-snapshot.sh resolves ./build/qemu-system-x86_64 from cwd.
	# sudo: background snapshots need userfaultfd, which is root-only by
	# default (vm.unprivileged_userfaultfd=0); the benchmark itself also
	# runs as root (TAP networking).
	(cd "$REPO_ROOT" && sudo ./tests/bench-bg-snapshot.sh 512 > /dev/null)
else
	echo "Skipping smoke test"
fi

echo "QEMU snapshot benchmark setup complete."
