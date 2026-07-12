# Serving volumes to VM guests

Status: exploration / survey. No implementation, no decision.

## Framing

ublk is the only front-end today. A VMM consumes a volume the same way
any host process does, by opening `/dev/ublkbN`. That works with every
VMM (qemu, cloud-hypervisor, Firecracker all accept a host block device
as a drive backing), but the data path for a guest crosses the kernel
twice per request, and ublk itself requires `ublk_drv` on the host.
Environments that cannot load kernel modules (inner containers such as
sprites.dev, hosts with `CAP_SYS_MODULE` stripped) cannot serve volumes
at all, even though the workload there is often exactly a VM.

The ublk chain for a guest request today, with each kernel crossing marked:

```
guest virtio-blk → VMM → syscall on /dev/ublkbN     (crossing 1: host block layer)
                 → ublk_drv → io_uring cmd → daemon  (crossing 2: ublk channel)
```

The volume side is already transport-agnostic. The ublk queue handler
dispatches every op to `VolumeReader` / `VolumeClient` (`src/ublk.rs`),
and a VM front-end would be a second consumer of the same interface, not
a change to the volume layer.

This document surveys the ways a VM guest's block I/O can reach a
userspace daemon on the host, and what each costs.

## The approaches

### vhost-user-blk

The VMM delegates the whole virtio-blk device to an external process
over a unix socket. Guest RAM is allocated fd-backed and `MAP_SHARED`
(qemu `memory-backend-memfd,share=on`, cloud-hypervisor
`--memory shared=on`), and the backend maps it. Virtqueue descriptors
and data are read and written in place, so the data path is zero-copy
with no host block device, no host block layer, and no per-request
syscall to move bytes. The unix socket carries control-plane setup only.

The host kernel keeps two roles. Doorbells and completions travel
through KVM ioeventfd/irqfd (a wakeup path, removable entirely by
polling the virtqueues), and the daemon's own I/O to segment files and
S3 remains ordinary file and network I/O. What is bypassed is the
virtual-disk plumbing, not the backing storage behind it.

Because the host page cache no longer sits in front of the disk image,
any caching or readahead the guest benefits from must live in the
daemon.

VMM support. qemu and cloud-hypervisor support it as a mature feature
(cloud-hypervisor ships its own backend crate, `vhost_user_block`).
Firecracker has frontend-only support since v1.6.0, still flagged
developer preview as of v1.16, and its docs describe this exact use
case as the motivating one (a backend "fetching the block device data
over the network or using sophisticated readahead logic").

Implementation surface. The rust-vmm crates (`vhost-user-backend`,
`virtio-queue`, `vm-memory`) are the standard building blocks;
virtiofsd and SPDK's vhost target are prior art. virtio-blk carries
READ / WRITE / FLUSH / DISCARD / WRITE_ZEROES, the same op surface the
ublk handler already maps onto `VolumeReader` / `VolumeClient`.

### qemu's userspace NBD client

qemu's block layer speaks NBD itself, so
`-drive file=nbd+unix:///?socket=…` reaches a userspace NBD server with
no host kernel block involvement and no shared guest memory. The daemon
never sees guest RAM; data is copied over the socket both ways. This is
the security inverse of vhost-user (better isolation, worse
performance) and the protocol is trivial to serve. qemu only.
cloud-hypervisor and Firecracker have no NBD client.

### VDUSE / vDPA

VDUSE (`/dev/vduse`, Linux 5.15+) is the kernel's framework for
software-emulated vDPA devices in userspace. The control path is
handled in the kernel by design, which is why the framework restricts
itself to virtio-blk and why the daemon can run unprivileged. A VDUSE
device attaches to the vDPA bus and is then consumed one of two ways.
Bound to `virtio-vdpa` it appears as a native `/dev/vdX` on the host.
Bound to `vhost-vdpa` it serves a VM (qemu and cloud-hypervisor both
support vhost-vdpa).

VDUSE is the one option that could replace ublk for host mounts and
serve VMs from a single device implementation. It also re-imports the
deployability problem, since it needs the `vduse` module plus vDPA-bus
netlink setup, so it does not help the no-module environments. It is a
younger, less-travelled stack than either ublk or vhost-user.

### vfio-user

A userspace process emulates an entire PCI device (in practice an NVMe
controller; SPDK's vfio-user NVMe target is the flagship, libvfio-user
the library). The memory model is the same shared-guest-RAM arrangement
as vhost-user and the implementation surface is the largest of any
option here, since the backend emulates PCI config space and NVMe admin
and I/O queues rather than plugging into a virtio transport.

What the guest sees is a real NVMe controller, and that buys several
things virtio-blk cannot. Guests need no virtio drivers at all, so
unmodified OS images (including Windows) attach without a driver disk.
The guest gets native NVMe multi-queue and can drive the device with
io_uring passthrough. NVMe namespaces give one controller several
distinct block devices, which maps naturally onto attaching several
volumes through a single emulated device. The command set carries
Deallocate (TRIM) and Write Zeroes, the same op surface the volume
layer serves today.

VMM support is the least settled of the shared-memory options.
cloud-hypervisor marks its vfio-user support experimental; qemu's
client support is recent. SPDK demonstrates the performance ceiling,
the highest surveyed here.

### In-guest network initiator

The guest runs an NVMe/TCP or iSCSI initiator over virtio-net (or a
vsock bridge) to a userspace target on the host. No VMM block device
exists at all, so this works with every VMM including Firecracker GA,
and the daemon never touches guest memory. It requires guest-side
configuration, pays network-stack overhead per request, and booting
from the volume needs extra machinery.

### FUSE file export

The daemon serves the volume as a file in a FUSE filesystem and any VMM
opens it as an ordinary file-backed disk (qemu-storage-daemon's FUSE
block export is this shape). Universal, including Firecracker GA. Every
request crosses the FUSE protocol with copies and the host page cache
sits between guest and daemon.

### TCMU

LIO's userspace backstore, the pre-ublk way to back a host block device
from userspace, SCSI-flavoured and slower. Superseded by ublk for the
host-device shape; listed for completeness only.

## Support and properties

| approach | qemu | cloud-hypervisor | Firecracker | kernel module | daemon sees guest RAM | host mount |
|---|---|---|---|---|---|---|
| ublk device as drive file | yes | yes | yes | `ublk_drv` | no | yes |
| vhost-user-blk | yes | yes | preview (v1.6+) | none | yes | no |
| qemu NBD client | yes | no | no | none | no | no |
| VDUSE + vhost-vdpa | yes | yes | no | `vduse` | granted ranges | yes (virtio-vdpa) |
| vfio-user NVMe | recent | experimental | no | none | yes | no |
| in-guest NVMe/TCP | yes | yes | yes | none (guest-side) | no | no |
| FUSE file export | yes | yes | yes | `fuse` (ubiquitous) | no | via the file |

## Security posture of the shared-memory options

Sharing guest memory with the backend is a vhost-user protocol
requirement, not a Firecracker quirk. Every frontend requires fd-backed
`MAP_SHARED` guest RAM, and the memfd is visible in the VMM's
`/proc/{pid}/fd` on all of them. Firecracker's docs are unusually
candid about the consequences (any host process that can read its
procfs tree can map guest memory; shared-mapping page faults measured
up to ~24% slower) because its jailer threat model treats same-uid
neighbours as untrusted. Outside that model the procfs exposure adds
little, since any same-uid process can already read a VMM's memory via
`/proc/{pid}/mem` or `process_vm_readv`.

The delta that matters for us is the daemon's own position. Serving
through ublk, the daemon never touches guest memory; kernel copies sit
between it and the guest, and a compromised daemon can return wrong
bytes but cannot read guest secrets or write guest kernel structures.
Serving through vhost-user (or vfio-user), the daemon holds a full
read-write mapping of guest RAM, so daemon compromise is guest
compromise. The trust arrow points both ways. The guest writes the
virtqueue descriptors the daemon parses, so the backend must treat
guest memory as hostile input (revalidate descriptor fields after
reading, no TOCTOU on lengths and offsets). The rust-vmm
`virtio-queue` / `vm-memory` crates exist largely to get this right.

vhost-user can be narrowed with a virtio-iommu, where the backend maps
only regions the guest has DMA-mapped, via IOTLB messages. qemu and
cloud-hypervisor support it. It costs performance, requires guest
cooperation, and is a lightly-travelled path for block devices.

## Integration notes

Two points are independent of which approach is chosen.

The front-end slot. Everything above terminates in the same
`VolumeReader` / `VolumeClient` dispatch the ublk handler uses, so a VM
front-end is an additional serve mode beside `run_volume_ublk`, not a
volume-layer change.

Attachment liveness. "Held" today means a live ublk device plus a
`volume.toml` claim, and the sweep machinery reasons about `/dev`
nodes. A socket-served VM attachment is a second kind of liveness (a
connected frontend on a unix socket) and the claim/sweep/connected-gate
machinery would need an equivalent notion for it.

## Assessment

Three approaches merit further exploration.

vhost-user-blk is the mainstream userspace-dataplane answer. It removes
the kernel-module dependency entirely, which makes VM serving possible
in exactly the environments where ublk is impossible, and it trades
ublk's kernel-mediated isolation for that; the daemon becomes
guest-trust-critical in both directions. Broadest VMM support and the
best-worn implementation path.

vfio-user is the heavier build, and the guest-sees-NVMe property makes
it worth exploring anyway. Unmodified guests without virtio drivers,
native multi-queue with io_uring passthrough in the guest, and NVMe
namespaces as a natural multi-volume attachment surface are
capabilities no virtio-based option offers. Its VMM support is the
least mature, so it reads as a second-generation front-end rather than
the first one to build.

VDUSE is the only option that unifies host mounts and VM serving in one
device implementation, replacing ublk rather than sitting beside it,
and its kernel-held control path is the strongest security posture of
the shared-dataplane options. It re-imports a module dependency
(`vduse`) on a younger stack, so it trades ublk's module problem for a
different module rather than eliminating it.

The remainder are fallbacks or non-starters. qemu's NBD client is a
low-effort qemu-only fallback with the opposite security/performance
trade. TCMU is legacy, and the universal fallbacks (FUSE, in-guest
initiators) give up the performance that motivates a VM front-end in
the first place.

Unless VDUSE is adopted wholesale, ublk remains the host-mount story
and any VM front-end is an addition beside it, not a replacement.
