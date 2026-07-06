# Quickstart

Deploy a standalone Elide coordinator on [Fly.io](https://fly.io) backed by
[Tigris](https://www.tigrisdata.com) object storage, create a block volume,
put a filesystem on it, and write a file. Part 2 moves the live volume to a
second machine.

This uses `deploy/elide-standalone/` — a simplified deployment where the
coordinator talks to Tigris directly with one read/write keypair. See
[deploy/elide-standalone/README.md](../deploy/elide-standalone/README.md) for
its security model, and `deploy/elide/` for the mint-backed alternative with
per-volume scoped credentials.

## Prerequisites

- A [Fly.io](https://fly.io) account and the [`fly` CLI](https://fly.io/docs/flyctl/install/), logged in (`fly auth login`)

Everything below runs from `deploy/elide-standalone/`:

```sh
cd deploy/elide-standalone
```

## 1. Launch

```sh
./launch
```

`launch` provisions and deploys in one step: it creates the Fly app
(auto-named `elide-<hex>`), asks for a region, creates a Tigris bucket
targeting the app — which sets the keypair secrets the coordinator signs
S3 operations with — writes `fly.toml`, and deploys the newest elide
release. It echoes each `fly` command as it runs it; `./launch <region>`
skips the prompt. The coordinator comes up serving immediately.

Use the app name `launch` chose wherever `my-elide` appears below. To pick
your own app name, reuse an existing bucket, or pin a release, run the same
steps by hand instead — see [Manual setup](#manual-setup).

## 2. Create an elide volume

The coordinator's control plane is a Unix socket inside the machine, so
volume operations run over SSH:

```sh
fly ssh console -a my-elide
```

Inside the machine:

```sh
elide volume create --size 1G vol1
```

The coordinator runs as root with `ublk_drv` loaded, so the volume comes up
serving a kernel block device: `/dev/ublkb0`.

## 3. Format, mount, write

Still inside the machine:

```sh
mkfs.ext4 /dev/ublkb0
mkdir -p /mnt/vol1
mount /dev/ublkb0 /mnt/vol1
echo "hello!" > /mnt/vol1/hello.txt
cat /mnt/vol1/hello.txt
```

Writes land in the volume's write-ahead log; the coordinator drains sealed
segments to Tigris automatically every few seconds. `elide volume list`
shows the volume's state, and `elide volume events vol1` shows its event
log.

## Part 2 — Move the volume to a second machine

A volume has exactly one owner. Handing it to another machine is
stop-and-release on the current owner, then claim-and-start on the new one —
the bucket is the sole rendezvous between the two coordinators.

### 1. Scale to two machines

Each machine needs its own `elide_data` Fly volume; `fly scale` offers to
create the second one:

```sh
fly scale count 2 -a my-elide
```

Get both machine IDs:

```sh
fly machine list -a my-elide
```

### 2. Release on machine 1

SSH to the machine that owns `vol1` (the original one):

```sh
fly ssh console -a my-elide --machine <machine1-id>
```

Inside:

```sh
umount /mnt/vol1
elide volume release vol1
```

`release` stops the volume — drains the remaining WAL to Tigris, publishes a
stop snapshot, detaches the block device — and then releases the name in the
bucket so any coordinator may claim it.

### 3. Claim on machine 2

SSH to the other machine:

```sh
fly ssh console -a my-elide --machine <machine2-id>
```

Inside:

```sh
elide volume claim vol1
elide volume start vol1
mkdir -p /mnt/vol1
mount /dev/ublkb0 /mnt/vol1
cat /mnt/vol1/hello.txt
# hello!
```

`claim` takes ownership of the released name; `start` serves it over ublk,
demand-fetching segment data from Tigris as it is read. (`elide volume start
vol1 --claim` does both in one step.)

## Manual setup

The steps `launch` runs, by hand — for a chosen app name, an existing
bucket, or a pinned release.

### 1. Create the Fly app

```sh
fly apps create my-elide
```

Pick your own app name — it's global across Fly. Use it wherever `my-elide`
appears in this guide.

### 2. Create a Tigris bucket

Create the bucket with the Tigris integration, targeting the app:

```sh
fly storage create -a my-elide -n my-elide-data
```

This sets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` on the app — the
two secrets the coordinator signs S3 operations with.

To use a bucket created another way (the Fly.io dashboard, an existing
bucket), copy its keypair from the Tigris console and set the secrets
directly:

```sh
fly secrets set -a my-elide AWS_ACCESS_KEY_ID=tid_… AWS_SECRET_ACCESS_KEY=tsec_…
```

Note the bucket name — `fly storage list` shows it — you'll need it in
step 3.

### 3. Configure fly.toml

```sh
cp fly.toml.example fly.toml
```

Edit `fly.toml`:

- `app` — your app name (`my-elide`)
- `primary_region` — your preferred [region](https://fly.io/docs/reference/regions/)
- `DATA_BUCKET` build arg — the Tigris bucket name from step 2; the
  Dockerfile bakes it into the coordinator's config

This completes the configuration: the Tigris endpoint and region are baked
into the image's `coord.toml`, and the keypair arrives via the secrets.

### 4. Deploy

```sh
fly deploy
```

The image runs the newest elide release, and the first deploy creates the
machine's `elide_data` Fly volume (10GB, from `initial_size` in fly.toml) —
coordinator state (segment indexes, cache, keys) lives there and survives
redeploys. `./deploy.sh v0.1.3` deploys a pinned release instead.

The coordinator comes up serving immediately. If the keypair secrets are
missing it fails loudly at startup.
