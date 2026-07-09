# Quickstart (via Fly.io)

The following demo guides us through launching a "standalone" Elide instance via Fly.io. We will create an Elide volume backed by Tigris object storage. This Elide volume is exposed as a block device and we can create a filesystem on the block device, mount it and write to it. Finally in Part 2 we demonstrate moving an Elide volume between two Fly.io machines.

## Prerequisites

* A [Fly.io](https://fly.io/) account
* [flyctl](https://fly.io/docs/flyctl/install/) installed locally 

```sh
# Login via flyctl
fly auth login

# Run the demo from the "elide-standalone" directory
cd deploy/elide-standalone
```

## Part 1 — Create and write to a volume

### 1. Launch

```sh
# launch.sh runs the following steps internally -
#
# fly apps create
# fly storage create
# writes a local fly.toml
# fly deploy
#
# Feel free to run these steps individually as desired
#
./launch.sh
```

Launching Elide will provision a Fly.io app (choosing a random name) and the associated Tigris storage bucket - 
* Fly.io app: `bright-smoke-973`
* Tigris bucket: `bright-smoke-973-data`

The machine boots with the ublk kernel module loaded and the Elide coordinator running, holding the bucket credentials Fly provisioned at deploy time.

### 2. Create an Elide volume

At this point we have a running app with a single machine instance. Creating a volume registers its name in the bucket and exposes it as a local block device at `/dev/elide/vol1`.

```sh
# Connect to the machine instance
fly ssh console

# Create a new Elide volume
elide volume create --size 1G vol1

# List Elide volumes
elide volume list

# View the status of an Elide volume
elide volume status vol1
```

### 3. Format, mount, write

The device behaves like any disk. Writes land on local storage and drain to the bucket asynchronously. The object store provides durability and the local copy acts as a cache.

```sh
# Create a filesystem on the block device
mkfs.ext4 /dev/elide/vol1

# Mount the filesystem
mkdir -p /mnt/vol1
mount -o discard /dev/elide/vol1 /mnt/vol1

# Write a file
echo "hello!" > /mnt/vol1/hello.txt

# Read the file
cat /mnt/vol1/hello.txt
```

## Part 2 — Volume release/claim

With two Fly.io machines we can demonstrate moving an Elide volume between instances. An Elide volume is owned _exclusively_ by a single instance - we will release it from one instance before claiming on another instance.

### 1. Scale to two machines

The second machine boots the same image and connects to the same Tigris bucket but holds no volume data locally.

```sh
# Make a second machine available by scaling the Fly.io app to 2 instances
fly scale count 2
```

### 2. Release the volume

Releasing drains any pending data to the bucket, publishes a snapshot for handoff, and releases the volume so another instance can claim it.

```sh
# Connect to the "original" machine
fly ssh console -s

# Detach the filesystem
umount /mnt/vol1

# Release the Elide volume
elide volume stop --release vol1
```

### 3. Claim the volume

Claiming moves ownership and the volume comes online immediately. A background prefetch warms the local cache from object storage, and anything not yet local is fetched on demand.

```sh
# Connect to the "new" machine
fly ssh console -s

# Claim the released volume
elide volume start --claim vol1

# Mount the filesystem and read the file we created previously
mkdir -p /mnt/vol1
mount -o discard /dev/elide/vol1 /mnt/vol1
cat /mnt/vol1/hello.txt
# hello!
```
