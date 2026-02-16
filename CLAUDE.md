# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

QEMU uses an out-of-tree build with Meson (wrapped by configure):

```bash
mkdir build && cd build
../configure                                          # basic config
../configure --target-list="x86_64-softmmu" --enable-debug  # targeted debug build
make -j$(nproc)
```

Rebuild a single binary quickly with ninja:
```bash
ninja -C build qemu-system-x86_64
```

## Testing

```bash
make -C build check                    # all quick tests
make -C build check-unit               # unit tests only
make -C build check-qtest              # device emulation tests
make -C build check-qtest-x86_64       # qtest for specific target
make -C build check-functional         # Python-based functional tests
make -C build check-block              # block layer (iotests)
make -C build check-tcg                # TCG translation tests
make -C build check-softfloat          # FPU emulation tests
make -C build check-qapi-schema        # QAPI schema validation
```

Run a single unit test directly:
```bash
./build/tests/unit/test-qdict
```

Run specific block tests:
```bash
cd build/tests/qemu-iotests && ./check -qcow2 001 030 153
```

Use `make -C build check-help` to see all test targets.

## Code Style

- 4-space indentation, no tabs (except Makefiles). 80-char soft line limit.
- C-style `/* */` comments only, not `//`.
- All indented statements must be braced, even single-line bodies.
- Function opening braces go on a **separate line**; control-flow opening braces go on the **same line**.
- Types use `CamelCase`; variables and functions use `lower_case_with_underscores`.
- Scalar typedefs end in `_t`. Public functions use a subsystem prefix (e.g., `tlb_`, `cpu_`).
- Declarations at the beginning of blocks (loop iterator variables in `for` are fine).

Check style before committing:
```bash
./scripts/checkpatch.pl -f path/to/file.c
```

## Architecture Overview

QEMU is a machine emulator and virtualizer. The major subsystems:

**Execution engines** (`accel/`): Pluggable accelerators — TCG (software JIT), KVM, HVF (macOS), Xen. TCG's host backends live in `tcg/<host-arch>/`.

**Guest CPU emulation** (`target/`): One directory per guest architecture (arm, i386, riscv, etc.) containing CPU models, instruction translation, and helpers.

**QOM — QEMU Object Model** (`qom/`, `include/qom/`): Object-oriented C type system with inheritance, properties, and introspection. All devices, CPUs, and machines are QOM objects.

**Device models** (`hw/`): The largest subsystem. Devices inherit from DeviceClass (defined in `hw/core/qdev.c`) and attach to buses (PCI, SysBus, I2C, USB, etc.). Organized by category: `hw/net/`, `hw/block/`, `hw/display/`, `hw/virtio/`, `hw/pci/`, etc. Machine/board definitions live in `hw/<arch>/`.

**QAPI** (`qapi/`): JSON schemas that auto-generate C types, QMP command handlers, and visitor code. The external management interface (used by libvirt) is defined here.

**Block layer** (`block/`): Stackable block drivers for disk formats (qcow2, raw, vmdk) and protocols (file, NBD, iSCSI). Uses coroutines for async I/O.

**Migration** (`migration/`): Live migration, savevm/loadvm, dirty page tracking.

**Monitor** (`monitor/`): HMP (human-readable) and QMP (JSON machine) interfaces, built on QAPI.

**System runtime** (`system/`): `vl.c` is the main initialization engine. `cpus.c` manages CPU threads. The Big QEMU Lock (BQL) serializes device access. Event loop is glib-based with coroutine support.

**Frontends**: `ui/` (GTK, SDL, VNC, Spice), `audio/`, `net/` (tap, slirp, vhost-user), `chardev/` (serial, socket, PTY).

## Key Patterns

- **Adding a device**: Create `hw/<category>/<device>.c`, implement a TypeInfo with a DeviceClass, register with `type_init()`. Wire properties, realize callback, and MMIO/PIO regions.
- **QAPI changes**: Edit JSON schemas in `qapi/`, then rebuild — C stubs are auto-generated. Run `make check-qapi-schema` to validate.
- **TCG instructions**: Add translation logic in `target/<arch>/translate*.c` using the TCG IR (intermediate representation) defined in `include/tcg/`.
- **Coroutines**: Block and I/O code uses `coroutine_fn` annotation and `qemu_coroutine_*` APIs for cooperative multitasking.
