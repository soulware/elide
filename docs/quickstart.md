# Quickstart

Import an OCI image, fork it, and serve it over NBD.

## Prerequisites

- Rust toolchain (`cargo`)
- `mke2fs` from e2fsprogs (macOS: `brew install e2fsprogs`)

## Build

```sh
cargo build -p elide -p elide-import
```

Binaries land in `target/debug/`.

## Import an OCI image

```sh
./target/debug/elide-import --image ubuntu:22.04 /tmp/elide-test/ubuntu-22.04
```

This pulls the image, builds an ext4 rootfs, and writes a readonly base volume. On Apple Silicon it auto-selects `arm64`; use `--arch amd64` to override.

The result:

```
/tmp/elide-test/ubuntu-22.04/
  meta.toml          — OCI source, digest, arch; readonly = true
  size               — volume size in bytes
  base/
    segments/        — imported data
    snapshots/
      <ulid>         — branch point for forks
```

## Fork

Create a writable fork from the base:

```sh
./target/debug/elide fork-volume /tmp/elide-test/ubuntu-22.04 vm1
```

The fork lands at `forks/vm1/` and its `origin` file points to `base/snapshots/<ulid>`.

## Serve over NBD

```sh
./target/debug/elide serve-volume /tmp/elide-test/ubuntu-22.04 vm1
```

Binds to `127.0.0.1:10809`. Leave it running in a separate terminal.

To bind on all interfaces (for VM access): `--bind 0.0.0.0`

## Connect with nbd-client

```sh
sudo nbd-client 127.0.0.1 10809 /dev/nbd0
sudo mount /dev/nbd0 /mnt
```

Or boot directly with QEMU — see [vm-boot.md](vm-boot.md).

## Import a raw ext4 image directly

If you already have an ext4 image (e.g. extracted from a cloud image), use `--from-file` to skip the OCI pull:

```sh
./target/debug/elide-import --from-file ubuntu-22.04.ext4 /tmp/elide-test/ubuntu-22.04
```

Note: `--image` and `--from-file` are mutually exclusive; `<vol_dir>` is always the positional argument.

## Boot-trace analysis on an OCI-derived volume

To measure what fraction of an OCI image is actually read during a VM boot, retain the intermediate flat ext4 at import time:

```sh
./target/debug/elide-import --image ubuntu:22.04 /tmp/elide-test/ubuntu-22.04 \
    --save-flat /tmp/ubuntu-22.04.ext4
```

Then serve it under the tracing NBD server and boot a VM:

```sh
./target/debug/elide serve /tmp/ubuntu-22.04.ext4 --save-trace /tmp/ubuntu-22.04.trace
```

(Boot the VM with `--drive file=nbd://127.0.0.1:10809,format=raw,if=virtio` or use `nbd-client` + QEMU direct kernel boot — see [vm-boot.md](vm-boot.md).)

Disconnect the VM and the trace is written. To compare two OCI versions (e.g. estimate delta-fetch cost when upgrading):

```sh
# Import the newer version
./target/debug/elide-import --image ubuntu:24.04 /tmp/elide-test/ubuntu-24.04 \
    --save-flat /tmp/ubuntu-24.04.ext4

# Cross-image cold-boot analysis: how much data must be fetched if you already
# have ubuntu:22.04 blocks cached?
./target/debug/elide cold-boot /tmp/ubuntu-22.04.ext4 /tmp/ubuntu-24.04.ext4 \
    --trace /tmp/ubuntu-22.04.trace
```

## Other useful commands

```sh
# Human-readable summary of the volume layout
./target/debug/elide inspect-volume /tmp/elide-test/ubuntu-22.04

# List forks
./target/debug/elide list-forks /tmp/elide-test/ubuntu-22.04

# Browse the ext4 filesystem without mounting
./target/debug/elide ls-volume /tmp/elide-test/ubuntu-22.04 vm1 /etc

# Snapshot a live fork (idempotent if no new writes)
./target/debug/elide snapshot-volume /tmp/elide-test/ubuntu-22.04 vm1

# Fork from a user fork instead of base
./target/debug/elide fork-volume /tmp/elide-test/ubuntu-22.04 vm2 --from vm1
```

