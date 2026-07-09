# Elide

Elide is a userspace block device, built on Linux [ublk](https://docs.kernel.org/block/ublk.html) and backed by remote object storage.
It is heavily inspired by the original Log-Structured Virtual Disk ([LSVD](https://doi.org/10.1145/3492321.3524271)) paper but extends the design, decoupling the logical layout from the physical storage layer through content identity.

Extents are identified by the hash of their contents, so identical data is stored once. Snapshots are cheap content manifests, and garbage collection compacts live data into fresh segments without touching the logical layout.
Data is written to fast direct-attached storage and asynchronously uploaded to object storage for durability. Reads are served from the local cache, with missing extents fetched from object storage on demand.

Elide targets [Tigris](https://www.tigrisdata.com/) object storage, which provides S3 semantics with low storage costs and free egress.

Because the bucket holds the durable copy and local storage is only a cache, volumes are portable: release a volume on one host and claim it on another, and it becomes available immediately. The volume is hydrated from object storage on demand. A volume has exactly one owner at a time.

```sh
# create a new Elide volume
elide volume create --size 1G vol1

# create a filesystem, mount it and write to it
mkfs.ext4 /dev/elide/vol1
mkdir -p /mnt/vol1 && mount /dev/elide/vol1 /mnt/vol1
echo "hello!" > /mnt/vol1/hello.txt

# release the volume from this host...
umount /mnt/vol1
elide volume stop --release vol1

# ...and claim it on another host, data fetched on demand
elide volume start --claim vol1
mkdir -p /mnt/vol1 && mount /dev/elide/vol1 /mnt/vol1
cat /mnt/vol1/hello.txt
# hello!
```

## Quickstart

The easiest way to get up and running with Elide is by deploying on [Fly.io](https://fly.io/).
This provides a VM with ublk support in the kernel and Tigris integration.

Start here for a walkthrough - [quickstart.md](docs/quickstart.md).
