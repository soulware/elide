# Quickstart: Empty Data Volume

Create a blank writable volume, mount it from a Linux VM, write data, and let the coordinator drain segments to the store automatically.

## Prerequisites

- Rust toolchain (`cargo`)
- A Linux VM with `nbd-client` available. The repo ships [`elide-dev.yaml`](../elide-dev.yaml), a [Lima](https://lima-vm.io/) config that provisions Ubuntu 24.04 with `nbd-client` and the `nbd` and `ublk_drv` modules pre-loaded; any VM with host network access works.

```sh
limactl start --name=elide-dev ./elide-dev.yaml   # first time only
limactl start elide-dev                            # subsequent boots
```

## Build and start the coordinator

```sh
cargo build -p elide -p elide-coordinator
./target/debug/elide-coordinator serve   # leave running in a separate terminal
```

With no config file: volume state in `elide_data/`, local store in `elide_store/`.

## Create the volume

```sh
./target/debug/elide volume create --size 1G data-vol
```

## Enable NBD

Write the desired port to `nbd.port`. The coordinator reads this at spawn time and passes `--port` to the volume process:

```sh
echo 10809 > elide_data/by_name/data-vol/nbd.port
./target/debug/elide volume status data-vol   # wait until "running"
```

## Connect from the VM

Lima exposes the host as `host.lima.internal` from inside the VM, so no gateway lookup is needed:

```sh
limactl shell elide-dev sudo nbd-client -b 4096 host.lima.internal 10809 /dev/nbd0
limactl shell elide-dev sudo mkfs.ext4 /dev/nbd0
limactl shell elide-dev sudo mount /dev/nbd0 /mnt
```

Format with `mkfs.ext4` on first use only; subsequent mounts skip this step.

## Tune the NBD queue (recommended)

The default kernel queue limits for `/dev/nbd0` are conservative: on a typical Ubuntu VM, `max_sectors_kb` is 128 and `read_ahead_kb` is 128, so every NBD request on the wire carries at most 128 KiB (32 blocks) and sequential readahead fills only one request ahead. The volume advertises a 4 MiB maximum block size during handshake, and `max_hw_sectors_kb` on the driver is 32 MiB, so there is significant headroom.

Raising both values lets sequential reads and writes coalesce into larger NBD requests, which amortises per-request overhead (extent index lookups, decompression frames, segment fetches) across larger windows:

```sh
limactl shell elide-dev sudo bash -c '
    echo 4096 > /sys/block/nbd0/queue/max_sectors_kb
    echo 4096 > /sys/block/nbd0/queue/read_ahead_kb
'
```

These settings reset when `/dev/nbd0` is disconnected and must be re-applied after each `nbd-client` run. To confirm the current values:

```sh
limactl shell elide-dev \
    cat /sys/block/nbd0/queue/{max_sectors_kb,max_hw_sectors_kb,read_ahead_kb,logical_block_size}
```

`logical_block_size` should read `4096` on current kernels; if it reads `512`, the client is ignoring the server's preferred-block-size hint and the volume falls back to a read-modify-write path for sub-4 KiB writes (correct but slower).

## Write data

```sh
limactl shell elide-dev \
    sudo bash -c 'dd if=/dev/urandom of=/mnt/bigfile bs=1M count=80 && sync'
```

The WAL flushes to `pending/` once it exceeds 32 MiB; 80 MiB produces two or three segments.

## Segments drain automatically

The coordinator uploads `pending/` segments to the store on each drain tick (default: every 5 seconds). No manual step required. Check progress:

```sh
./target/debug/elide volume info data-vol
```

After drain, segments are uploaded to `elide_store/` and promoted: the volume writes `index/<ulid>.idx` (permanent LBA index) and `cache/<ulid>.body` (evictable body), then removes the `pending/` file.

## Volume directory layout

```
elide_data/by_id/<ulid>/
  wal/
    <ulid>          — active WAL (unflushed remainder between drain ticks)
  pending/          — empty between ticks; segments here are uploading
  index/
    <ulid>.idx      — LBA index section; written at flush; permanent (survives eviction)
  cache/
    <ulid>.body     — segment body; evictable once committed to store
  volume.name       — "data-vol"
  volume.size       — "1073741824"
  volume.key        — Ed25519 signing key (never uploaded)
  volume.pub        — Ed25519 public key
  volume.provenance — signed lineage (parent + extent_index); uploaded to S3
  volume.pid        — PID of running volume process
  nbd.port          — "10809"
  control.sock      — volume IPC socket
  volume.lock       — exclusive lock held while running
```

## Disconnect

```sh
limactl shell elide-dev sudo umount /mnt
limactl shell elide-dev sudo nbd-client -d /dev/nbd0
```

The coordinator keeps the volume process running after disconnect. Reconnect with `nbd-client` at any time.

## Troubleshooting

**`nbd-client -d` leaves the device in a bad state:**

```sh
limactl shell elide-dev sudo rmmod nbd
limactl shell elide-dev sudo modprobe nbd
```

**Stale lock file** (if the volume process crashed and the coordinator has not yet restarted it):

```sh
rm elide_data/by_name/data-vol/volume.lock
```

The coordinator will restart the volume on the next scan.
