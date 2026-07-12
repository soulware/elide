//! vhost-user-blk transport (dataplane).
//!
//! Serves one volume as the backend of a vhost-user block device on a
//! unix socket. The VMM is the frontend: it connects, negotiates
//! features, shares its guest-memory regions as fds, and hands us one
//! virtqueue. From then on the guest's virtio-blk driver places
//! requests in that queue in shared memory and we serve them directly —
//! no host block device, no kernel module.
//!
//! The `vhost-user-backend` crate runs the socket, memory-table, and
//! epoll plumbing; our side is [`imp::VhostBlkBackend`] (feature and
//! config-space negotiation) and [`imp::VolumeIo`] (virtio-blk request
//! parsing and dispatch onto `VolumeReader` / `VolumeClient` — the same
//! five ops the ublk handler maps).
//!
//! Single queue, synchronous dispatch on the daemon's queue-handler
//! thread, and request payloads bounce through a per-queue scratch
//! buffer. `blk_size = 4096` is advertised, so compliant drivers issue
//! 4K-aligned I/O; anything unaligned is completed with `IOERR` — no
//! RMW path, matching the ublk transport.
//!
//! The daemon serves one frontend connection and returns when the VMM
//! disconnects. qemu attach:
//!
//! ```text
//! qemu-system-x86_64 \
//!   -object memory-backend-memfd,id=mem,size=4G,share=on -numa node,memdev=mem \
//!   -chardev socket,id=vblk,path=<socket> \
//!   -device vhost-user-blk-pci,chardev=vblk
//! ```
//!
//! On non-Linux targets, and on Linux without the `vhost` cargo feature,
//! this module compiles to a stub that errors when the transport is
//! invoked.

use std::io;
use std::path::Path;

#[cfg(all(target_os = "linux", feature = "vhost"))]
mod imp {
    use std::io::{self, Read, Write};
    use std::ops::Deref;
    use std::path::Path;
    use std::sync::{Arc, Mutex, RwLock, RwLockWriteGuard};

    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
    use vhost_user_backend::{
        VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringState, VringT,
    };
    use virtio_bindings::virtio_blk::{
        VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_SEG_MAX,
        VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES, VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_IOERR,
        VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_FLUSH,
        VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VIRTIO_BLK_T_WRITE_ZEROES,
        VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP,
    };
    use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
    use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
    use virtio_queue::{DescriptorChain, QueueT, Reader, Writer};
    use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
    use vmm_sys_util::epoll::EventSet;

    use elide_core::actor::{VolumeClient, VolumeReader};

    pub(super) type Mem = GuestMemoryAtomic<GuestMemoryMmap<()>>;

    const BLOCK: u64 = 4096;
    /// virtio-blk wire unit: `sector` in every request header is in
    /// 512-byte units regardless of the advertised `blk_size`.
    const SECTOR: u64 = 512;
    const SECTORS_PER_BLOCK: u32 = (BLOCK / SECTOR) as u32;

    const QUEUE_SIZE: usize = 256;
    /// One head slot for the request header and one for the status byte.
    const SEG_MAX: u32 = QUEUE_SIZE as u32 - 2;
    /// Largest single data segment. Matches the ublk per-I/O buffer cap.
    const SIZE_MAX: u32 = 1 << 20;
    /// Cap on a single discard / write-zeroes range, in 512-byte sectors
    /// (512 MiB). Advertised in the config space; drivers split larger
    /// ranges.
    const MAX_DISCARD_SECTORS: u32 = 1 << 20;

    const S_OK: u8 = VIRTIO_BLK_S_OK as u8;
    const S_IOERR: u8 = VIRTIO_BLK_S_IOERR as u8;
    const S_UNSUPP: u8 = VIRTIO_BLK_S_UNSUPP as u8;

    /// virtio-blk config space, as read by the frontend via
    /// `VHOST_USER_GET_CONFIG`. Field layout per the virtio spec.
    // Wire-format struct: the fields pin the byte layout and are read
    // through `ByteValued::as_slice`, not field access.
    #[allow(dead_code)]
    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C, packed)]
    struct VirtioBlkConfig {
        capacity: u64,
        size_max: u32,
        seg_max: u32,
        cylinders: u16,
        heads: u8,
        sectors: u8,
        blk_size: u32,
        physical_block_exp: u8,
        alignment_offset: u8,
        min_io_size: u16,
        opt_io_size: u32,
        writeback: u8,
        unused: u8,
        num_queues: u16,
        max_discard_sectors: u32,
        max_discard_seg: u32,
        discard_sector_alignment: u32,
        max_write_zeroes_sectors: u32,
        max_write_zeroes_seg: u32,
        write_zeroes_may_unmap: u8,
        unused1: [u8; 3],
    }

    // SAFETY: packed struct of plain integers, no padding, any bit
    // pattern is a valid value.
    unsafe impl ByteValued for VirtioBlkConfig {}

    impl VirtioBlkConfig {
        fn for_volume(size_bytes: u64) -> Self {
            Self {
                capacity: size_bytes / SECTOR,
                size_max: SIZE_MAX,
                seg_max: SEG_MAX,
                blk_size: BLOCK as u32,
                min_io_size: 1,
                opt_io_size: 1,
                num_queues: 1,
                max_discard_sectors: MAX_DISCARD_SECTORS,
                max_discard_seg: 1,
                discard_sector_alignment: SECTORS_PER_BLOCK,
                max_write_zeroes_sectors: MAX_DISCARD_SECTORS,
                max_write_zeroes_seg: 1,
                write_zeroes_may_unmap: 1,
                ..Default::default()
            }
        }
    }

    /// Leading 16 bytes of every virtio-blk request.
    // Wire-format struct: `reserved` exists to pin the byte layout and
    // is populated through `Reader::read_obj`, never read by name.
    #[allow(dead_code)]
    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    struct RequestHeader {
        request_type: u32,
        reserved: u32,
        sector: u64,
    }

    // SAFETY: repr(C) struct of u32/u32/u64 — no padding, any bit
    // pattern is a valid value.
    unsafe impl ByteValued for RequestHeader {}

    /// Payload element of a DISCARD / WRITE_ZEROES request.
    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    struct DiscardSegment {
        sector: u64,
        num_sectors: u32,
        flags: u32,
    }

    // SAFETY: repr(C) struct of u64/u32/u32 — no padding, any bit
    // pattern is a valid value.
    unsafe impl ByteValued for DiscardSegment {}

    /// Per-queue I/O state: the volume handle, a scratch buffer request
    /// payloads bounce through, and the negotiated EVENT_IDX flag.
    /// Wrapped in a `Mutex` inside the backend because `VolumeReader`
    /// is `Send` but not `Sync`; only the queue-handler thread ever
    /// locks it.
    pub(super) struct VolumeIo {
        reader: VolumeReader,
        scratch: Vec<u8>,
        size_bytes: u64,
        serial: [u8; VIRTIO_BLK_ID_BYTES as usize],
        event_idx: bool,
    }

    impl VolumeIo {
        fn new(
            reader: VolumeReader,
            size_bytes: u64,
            serial: [u8; VIRTIO_BLK_ID_BYTES as usize],
        ) -> Self {
            Self {
                reader,
                scratch: Vec::new(),
                size_bytes,
                serial,
                event_idx: false,
            }
        }

        /// Drain every available descriptor chain once. Returns whether
        /// any chain was consumed.
        fn process_queue(
            &mut self,
            mem: &Mem,
            vring: &mut RwLockWriteGuard<VringState<Mem>>,
        ) -> bool {
            let m = mem.memory();
            let mut used = false;
            while let Some(chain) = vring.get_queue_mut().pop_descriptor_chain(mem.memory()) {
                let head = chain.head_index();
                let len = self.process_chain(m.deref(), chain);
                if let Err(e) = vring.get_queue_mut().add_used(m.deref(), head, len) {
                    tracing::error!("[vhost-blk add_used failed: {e}]");
                    break;
                }
                used = true;
            }
            if used {
                let signal = if self.event_idx {
                    vring
                        .get_queue_mut()
                        .needs_notification(m.deref())
                        .unwrap_or(true)
                } else {
                    true
                };
                if signal && let Err(e) = vring.signal_used_queue() {
                    tracing::error!("[vhost-blk signal_used_queue failed: {e}]");
                }
            }
            used
        }

        /// Execute one descriptor chain and return the used-ring length
        /// (bytes written to device-writable descriptors, including the
        /// status byte). A chain too malformed to carry a status byte is
        /// consumed with length 0.
        fn process_chain<M>(&mut self, mem: &GuestMemoryMmap<()>, chain: DescriptorChain<M>) -> u32
        where
            M: Clone + Deref<Target = GuestMemoryMmap<()>>,
        {
            let mut reader: Reader<'_> = match Reader::new(mem, chain.clone()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("[vhost-blk bad readable chain: {e}]");
                    return 0;
                }
            };
            let mut writer: Writer<'_> = match Writer::new(mem, chain) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("[vhost-blk bad writable chain: {e}]");
                    return 0;
                }
            };
            let writable = writer.available_bytes();
            if writable == 0 {
                tracing::error!("[vhost-blk chain has no status descriptor]");
                return 0;
            }
            // Carve the status byte (last writable byte of the chain) off
            // so `execute` sees only the data area.
            let mut status_writer = match writer.split_at(writable - 1) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("[vhost-blk status split failed: {e}]");
                    return 0;
                }
            };
            let (status, data_len) = self.execute(&mut reader, &mut writer);
            if let Err(e) = status_writer.write_obj(status) {
                tracing::error!("[vhost-blk status write failed: {e}]");
                return 0;
            }
            data_len + 1
        }

        fn execute(&mut self, reader: &mut Reader<'_>, writer: &mut Writer<'_>) -> (u8, u32) {
            let hdr: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("[vhost-blk short request header: {e}]");
                    return (S_IOERR, 0);
                }
            };
            match hdr.request_type {
                VIRTIO_BLK_T_IN => {
                    let len = writer.available_bytes();
                    if len == 0 {
                        return (S_OK, 0);
                    }
                    let (lba, _) = match self.check_range(hdr.sector, len as u64) {
                        Ok(v) => v,
                        Err(s) => return (s, 0),
                    };
                    self.scratch.resize(len, 0);
                    if let Err(e) = self.reader.read_into(lba, &mut self.scratch[..len]) {
                        tracing::error!("[vhost-blk read error sector={} len={len}: {e}]", {
                            hdr.sector
                        });
                        return (S_IOERR, 0);
                    }
                    match writer.write_all(&self.scratch[..len]) {
                        Ok(()) => (S_OK, len as u32),
                        Err(e) => {
                            tracing::error!("[vhost-blk guest-memory write failed: {e}]");
                            (S_IOERR, 0)
                        }
                    }
                }
                VIRTIO_BLK_T_OUT => {
                    let len = reader.available_bytes();
                    if len == 0 {
                        return (S_OK, 0);
                    }
                    let (lba, _) = match self.check_range(hdr.sector, len as u64) {
                        Ok(v) => v,
                        Err(s) => return (s, 0),
                    };
                    self.scratch.resize(len, 0);
                    if let Err(e) = reader.read_exact(&mut self.scratch[..len]) {
                        tracing::error!("[vhost-blk guest-memory read failed: {e}]");
                        return (S_IOERR, 0);
                    }
                    match self.reader.write(lba, &self.scratch[..len]) {
                        Ok(()) => (S_OK, 0),
                        Err(e) => {
                            tracing::error!("[vhost-blk write error sector={} len={len}: {e}]", {
                                hdr.sector
                            });
                            (S_IOERR, 0)
                        }
                    }
                }
                VIRTIO_BLK_T_FLUSH => match self.reader.flush() {
                    Ok(()) => (S_OK, 0),
                    Err(e) => {
                        tracing::error!("[vhost-blk flush error: {e}]");
                        (S_IOERR, 0)
                    }
                },
                VIRTIO_BLK_T_GET_ID => {
                    let len = writer.available_bytes().min(self.serial.len());
                    match writer.write_all(&self.serial[..len]) {
                        Ok(()) => (S_OK, len as u32),
                        Err(e) => {
                            tracing::error!("[vhost-blk serial write failed: {e}]");
                            (S_IOERR, 0)
                        }
                    }
                }
                VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_WRITE_ZEROES => {
                    self.discard_or_write_zeroes(hdr.request_type, reader)
                }
                other => {
                    tracing::warn!("[vhost-blk unsupported request type {other}]");
                    (S_UNSUPP, 0)
                }
            }
        }

        fn discard_or_write_zeroes(
            &mut self,
            request_type: u32,
            reader: &mut Reader<'_>,
        ) -> (u8, u32) {
            let seg_bytes = std::mem::size_of::<DiscardSegment>();
            let avail = reader.available_bytes();
            if avail == 0 || !avail.is_multiple_of(seg_bytes) {
                return (S_IOERR, 0);
            }
            // max_discard_seg / max_write_zeroes_seg = 1 is advertised;
            // a compliant driver never sends more than one segment.
            if avail / seg_bytes > 1 {
                return (S_UNSUPP, 0);
            }
            let seg: DiscardSegment = match reader.read_obj() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("[vhost-blk short discard segment: {e}]");
                    return (S_IOERR, 0);
                }
            };
            let unmap_only = VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP as u32;
            if seg.flags & !unmap_only != 0 {
                return (S_UNSUPP, 0);
            }
            if request_type == VIRTIO_BLK_T_DISCARD && seg.flags & unmap_only != 0 {
                // The unmap flag is reserved for WRITE_ZEROES.
                return (S_UNSUPP, 0);
            }
            let len_bytes = u64::from(seg.num_sectors) * SECTOR;
            let (lba, lba_count) = match self.check_range(seg.sector, len_bytes) {
                Ok(v) => v,
                Err(s) => return (s, 0),
            };
            let result = if request_type == VIRTIO_BLK_T_DISCARD {
                self.reader.trim(lba, lba_count)
            } else {
                self.reader.write_zeroes(lba, lba_count)
            };
            match result {
                Ok(()) => (S_OK, 0),
                Err(e) => {
                    tracing::error!(
                        "[vhost-blk discard/write-zeroes error sector={} count={}: {e}]",
                        { seg.sector },
                        { seg.num_sectors }
                    );
                    (S_IOERR, 0)
                }
            }
        }

        /// Validate a request range against alignment and capacity.
        /// `blk_size = 4096` is advertised, so compliant drivers only
        /// issue 4K-aligned I/O; anything else is refused rather than
        /// read-modify-written. Returns `(start_lba, lba_count)` in 4K
        /// units, or the status byte to complete the request with.
        fn check_range(&self, sector: u64, len_bytes: u64) -> Result<(u64, u32), u8> {
            let offset = sector.checked_mul(SECTOR).ok_or(S_IOERR)?;
            let end = offset.checked_add(len_bytes).ok_or(S_IOERR)?;
            if !offset.is_multiple_of(BLOCK) || !len_bytes.is_multiple_of(BLOCK) {
                tracing::error!("[vhost-blk unaligned request sector={sector} len={len_bytes}]");
                return Err(S_IOERR);
            }
            if end > self.size_bytes {
                tracing::error!("[vhost-blk out-of-range request sector={sector} len={len_bytes}]");
                return Err(S_IOERR);
            }
            Ok((offset / BLOCK, (len_bytes / BLOCK) as u32))
        }
    }

    pub(super) struct VhostBlkBackend {
        io: Mutex<VolumeIo>,
        config: VirtioBlkConfig,
        mem: Mem,
    }

    impl VhostBlkBackend {
        fn new(
            reader: VolumeReader,
            size_bytes: u64,
            serial: [u8; VIRTIO_BLK_ID_BYTES as usize],
            mem: Mem,
        ) -> Self {
            Self {
                io: Mutex::new(VolumeIo::new(reader, size_bytes, serial)),
                config: VirtioBlkConfig::for_volume(size_bytes),
                mem,
            }
        }
    }

    impl VhostUserBackendMut for VhostBlkBackend {
        type Bitmap = ();
        type Vring = VringRwLock<Mem>;

        fn num_queues(&self) -> usize {
            1
        }

        fn max_queue_size(&self) -> usize {
            QUEUE_SIZE
        }

        fn features(&self) -> u64 {
            (1 << VIRTIO_F_VERSION_1)
                | (1 << VIRTIO_RING_F_EVENT_IDX)
                | (1 << VIRTIO_BLK_F_FLUSH)
                | (1 << VIRTIO_BLK_F_BLK_SIZE)
                | (1 << VIRTIO_BLK_F_SEG_MAX)
                | (1 << VIRTIO_BLK_F_TOPOLOGY)
                | (1 << VIRTIO_BLK_F_DISCARD)
                | (1 << VIRTIO_BLK_F_WRITE_ZEROES)
                | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::CONFIG
        }

        fn set_event_idx(&mut self, enabled: bool) {
            if let Ok(io) = self.io.get_mut() {
                io.event_idx = enabled;
            }
        }

        fn update_memory(&mut self, _mem: Mem) -> io::Result<()> {
            Ok(())
        }

        fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
            let start = offset as usize;
            let end = start.saturating_add(size as usize);
            self.config
                .as_slice()
                .get(start..end)
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        }

        fn queues_per_thread(&self) -> Vec<u64> {
            vec![1]
        }

        fn handle_event(
            &mut self,
            device_event: u16,
            evset: EventSet,
            vrings: &[Self::Vring],
            _thread_id: usize,
        ) -> io::Result<()> {
            if evset != EventSet::IN {
                return Err(io::Error::other("unexpected event set"));
            }
            if device_event != 0 || vrings.len() != 1 {
                return Err(io::Error::other("unexpected device event"));
            }
            let mem = self.mem.clone();
            let io = self
                .io
                .get_mut()
                .map_err(|_| io::Error::other("vhost-blk io state poisoned"))?;
            let mut vring = vrings[0].get_mut();
            if io.event_idx {
                // With EVENT_IDX the guest may suppress our kick; keep
                // draining until a pass finds the queue empty with
                // notifications re-enabled, or requests race in forever.
                loop {
                    vring
                        .get_queue_mut()
                        .enable_notification(mem.memory().deref())
                        .map_err(io::Error::other)?;
                    if !io.process_queue(&mem, &mut vring) {
                        break;
                    }
                }
            } else {
                io.process_queue(&mem, &mut vring);
            }
            Ok(())
        }
    }

    /// Serial the guest reads via GET_ID: the volume-directory basename
    /// (its ULID), truncated to the 20 bytes virtio-blk allows.
    fn serial_for_volume(dir: &Path) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        let mut serial = [0u8; VIRTIO_BLK_ID_BYTES as usize];
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let bytes = name.as_bytes();
        let n = bytes.len().min(serial.len());
        serial[..n].copy_from_slice(&bytes[..n]);
        serial
    }

    /// Serve `client` on `socket` for a single frontend connection.
    /// Returns when the frontend disconnects; flushes the volume on the
    /// way out so every accepted write is durable.
    fn serve_socket(
        client: VolumeClient,
        size_bytes: u64,
        serial: [u8; VIRTIO_BLK_ID_BYTES as usize],
        socket: &Path,
    ) -> io::Result<()> {
        let mem: Mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());
        let backend = Arc::new(RwLock::new(VhostBlkBackend::new(
            client.reader(),
            size_bytes,
            serial,
            mem.clone(),
        )));
        let mut daemon = VhostUserDaemon::new("elide-vhost-blk".to_owned(), backend, mem)
            .map_err(|e| io::Error::other(format!("vhost-user daemon: {e}")))?;
        tracing::info!("[vhost-blk listening on {}]", socket.display());
        daemon
            .serve(socket)
            .map_err(|e| io::Error::other(format!("vhost-user serve: {e}")))?;
        tracing::info!("[vhost-blk frontend disconnected]");
        client.flush()
    }

    pub fn run_volume_vhost_blk(
        dir: &Path,
        size_bytes: u64,
        socket: &Path,
        fetch_inputs: crate::VolumeFetchInputs,
    ) -> io::Result<()> {
        let by_id_dir = dir.parent().unwrap_or(dir);
        let mut volume = crate::volume_open::open_volume_with_retry(dir, by_id_dir)?;
        let _peer_counters = crate::attach_demand_fetch(dir, &mut volume, fetch_inputs)?;
        let (actor, client) = elide_core::actor::spawn(volume);
        std::thread::Builder::new()
            .name("volume-actor".into())
            .spawn(move || actor.run())
            .map_err(io::Error::other)?;
        serve_socket(client, size_bytes, serial_for_volume(dir), socket)
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::{AtomicU64, Ordering};

        use elide_core::actor::VolumeClient;
        use elide_core::volume::Volume;
        use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
        use virtio_queue::desc::{RawDescriptor, split::Descriptor as SplitDescriptor};
        use virtio_queue::mock::MockSplitQueue;
        use virtio_queue::{Queue, QueueOwnedT};
        use vm_memory::{Bytes, GuestAddress};

        use super::*;

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        const VOL_SIZE: u64 = 1 << 20;

        fn temp_dir() -> std::path::PathBuf {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!("elide-vhost-test-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            elide_core::signing::generate_keypair(
                &p,
                elide_core::signing::VOLUME_KEY_FILE,
                elide_core::signing::VOLUME_PUB_FILE,
            )
            .unwrap();
            p
        }

        /// Live VolumeIo backed by a scratch volume. The client is
        /// returned so the actor thread stays up (and so tests can issue
        /// out-of-band writes/reads to verify against).
        fn spawn_volume_io() -> (std::path::PathBuf, VolumeClient, VolumeIo) {
            let dir = temp_dir();
            let volume = Volume::open(&dir, &dir).unwrap();
            let (actor, client) = elide_core::actor::spawn(volume);
            std::thread::Builder::new()
                .name("vhost-test-actor".into())
                .spawn(move || actor.run())
                .unwrap();
            let io = VolumeIo::new(client.reader(), VOL_SIZE, *b"01TESTSERIAL00000000");
            (dir, client, io)
        }

        fn guest_mem() -> GuestMemoryMmap<()> {
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 1 << 20)]).unwrap()
        }

        /// Build a descriptor chain in `mem`. Each entry is
        /// `(device_writable, len)`; buffers are laid out contiguously
        /// after the mock queue's rings. Returns the popped chain plus
        /// each descriptor's buffer address.
        fn build_chain<'a>(
            mem: &'a GuestMemoryMmap<()>,
            descs: &[(bool, u32)],
        ) -> (DescriptorChain<&'a GuestMemoryMmap<()>>, Vec<GuestAddress>) {
            let mock = MockSplitQueue::new(mem, 16);
            let mut addr = mock.end();
            let mut raw = Vec::new();
            let mut addrs = Vec::new();
            for (i, (writable, len)) in descs.iter().enumerate() {
                let mut flags = if *writable { VRING_DESC_F_WRITE } else { 0 };
                if i + 1 < descs.len() {
                    flags |= VRING_DESC_F_NEXT;
                }
                raw.push(RawDescriptor::from(SplitDescriptor::new(
                    addr.0,
                    *len,
                    flags as u16,
                    (i + 1) as u16,
                )));
                addrs.push(addr);
                addr = GuestAddress(addr.0 + u64::from(*len));
            }
            mock.build_desc_chain(&raw).unwrap();
            let mut queue: Queue = Queue::new(16).unwrap();
            queue
                .try_set_desc_table_address(mock.desc_table_addr())
                .unwrap();
            queue.try_set_avail_ring_address(mock.avail_addr()).unwrap();
            queue.try_set_used_ring_address(mock.used_addr()).unwrap();
            queue.set_ready(true);
            let chain = queue.iter(mem).unwrap().next().unwrap();
            (chain, addrs)
        }

        fn header(request_type: u32, sector: u64) -> RequestHeader {
            RequestHeader {
                request_type,
                reserved: 0,
                sector,
            }
        }

        /// Run one request through `process_chain`. Returns the used-ring
        /// length and the status byte.
        fn run_request(
            io: &mut VolumeIo,
            mem: &GuestMemoryMmap<()>,
            hdr: RequestHeader,
            descs: &[(bool, u32)],
            payload: Option<&[u8]>,
        ) -> (u32, u8, Vec<GuestAddress>) {
            let (chain, addrs) = build_chain(mem, descs);
            mem.write_obj(hdr, addrs[0]).unwrap();
            if let Some(data) = payload {
                mem.write_slice(data, addrs[1]).unwrap();
            }
            let used = io.process_chain(mem, chain);
            let status: u8 = mem.read_obj(*addrs.last().unwrap()).unwrap();
            (used, status, addrs)
        }

        #[test]
        fn write_then_read_roundtrip() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();

            let data = vec![0xabu8; 2 * BLOCK as usize];
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_OUT, 0),
                &[(false, 16), (false, data.len() as u32), (true, 1)],
                Some(&data),
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, 1);

            let (used, status, addrs) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_IN, 0),
                &[(false, 16), (true, data.len() as u32), (true, 1)],
                None,
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, data.len() as u32 + 1);
            let mut back = vec![0u8; data.len()];
            mem.read_slice(&mut back, addrs[1]).unwrap();
            assert_eq!(back, data);
            drop(client);
        }

        #[test]
        fn read_spans_multiple_data_descriptors() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();

            let data = vec![0x5au8; 2 * BLOCK as usize];
            let (_, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_OUT, 0),
                &[(false, 16), (false, data.len() as u32), (true, 1)],
                Some(&data),
            );
            assert_eq!(status, S_OK);

            // 8K read split across two 4K writable descriptors.
            let (chain, addrs) = build_chain(
                &mem,
                &[
                    (false, 16),
                    (true, BLOCK as u32),
                    (true, BLOCK as u32),
                    (true, 1),
                ],
            );
            mem.write_obj(header(VIRTIO_BLK_T_IN, 0), addrs[0]).unwrap();
            let used = io.process_chain(&mem, chain);
            assert_eq!(used, data.len() as u32 + 1);
            let status: u8 = mem.read_obj(addrs[3]).unwrap();
            assert_eq!(status, S_OK);
            for (i, buf_addr) in [addrs[1], addrs[2]].into_iter().enumerate() {
                let mut back = vec![0u8; BLOCK as usize];
                mem.read_slice(&mut back, buf_addr).unwrap();
                assert_eq!(back, data[i * BLOCK as usize..(i + 1) * BLOCK as usize]);
            }
            drop(client);
        }

        #[test]
        fn flush_completes_ok() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_FLUSH, 0),
                &[(false, 16), (true, 1)],
                None,
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, 1);
            drop(client);
        }

        #[test]
        fn write_zeroes_zeroes_the_range() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();

            let data = vec![0xffu8; 2 * BLOCK as usize];
            let (_, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_OUT, 0),
                &[(false, 16), (false, data.len() as u32), (true, 1)],
                Some(&data),
            );
            assert_eq!(status, S_OK);

            let seg = DiscardSegment {
                sector: 0,
                num_sectors: SECTORS_PER_BLOCK,
                flags: 0,
            };
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_WRITE_ZEROES, 0),
                &[(false, 16), (false, 16), (true, 1)],
                Some(seg.as_slice()),
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, 1);

            let (_, status, addrs) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_IN, 0),
                &[(false, 16), (true, 2 * BLOCK as u32), (true, 1)],
                None,
            );
            assert_eq!(status, S_OK);
            let mut back = vec![0u8; 2 * BLOCK as usize];
            mem.read_slice(&mut back, addrs[1]).unwrap();
            assert_eq!(&back[..BLOCK as usize], &vec![0u8; BLOCK as usize][..]);
            assert_eq!(&back[BLOCK as usize..], &vec![0xffu8; BLOCK as usize][..]);
            drop(client);
        }

        #[test]
        fn discard_completes_ok() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();

            let data = vec![0x11u8; BLOCK as usize];
            let (_, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_OUT, 0),
                &[(false, 16), (false, data.len() as u32), (true, 1)],
                Some(&data),
            );
            assert_eq!(status, S_OK);

            let seg = DiscardSegment {
                sector: 0,
                num_sectors: SECTORS_PER_BLOCK,
                flags: 0,
            };
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_DISCARD, 0),
                &[(false, 16), (false, 16), (true, 1)],
                Some(seg.as_slice()),
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, 1);
            drop(client);
        }

        #[test]
        fn discard_with_unmap_flag_is_unsupported() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let seg = DiscardSegment {
                sector: 0,
                num_sectors: SECTORS_PER_BLOCK,
                flags: VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP as u32,
            };
            let (_, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_DISCARD, 0),
                &[(false, 16), (false, 16), (true, 1)],
                Some(seg.as_slice()),
            );
            assert_eq!(status, S_UNSUPP);
            drop(client);
        }

        #[test]
        fn unaligned_read_fails_with_ioerr() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            // sector 1 = byte offset 512, not 4K-aligned.
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_IN, 1),
                &[(false, 16), (true, BLOCK as u32), (true, 1)],
                None,
            );
            assert_eq!(status, S_IOERR);
            assert_eq!(used, 1);
            drop(client);
        }

        #[test]
        fn out_of_range_read_fails_with_ioerr() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let last_sector = VOL_SIZE / SECTOR;
            let (_, status, _) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_IN, last_sector),
                &[(false, 16), (true, BLOCK as u32), (true, 1)],
                None,
            );
            assert_eq!(status, S_IOERR);
            drop(client);
        }

        #[test]
        fn get_id_returns_serial() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let (used, status, addrs) = run_request(
                &mut io,
                &mem,
                header(VIRTIO_BLK_T_GET_ID, 0),
                &[(false, 16), (true, VIRTIO_BLK_ID_BYTES), (true, 1)],
                None,
            );
            assert_eq!(status, S_OK);
            assert_eq!(used, VIRTIO_BLK_ID_BYTES + 1);
            let mut id = [0u8; VIRTIO_BLK_ID_BYTES as usize];
            mem.read_slice(&mut id, addrs[1]).unwrap();
            assert_eq!(&id, b"01TESTSERIAL00000000");
            drop(client);
        }

        #[test]
        fn unknown_request_type_is_unsupported() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let (used, status, _) = run_request(
                &mut io,
                &mem,
                header(0xdead_beef, 0),
                &[(false, 16), (true, 1)],
                None,
            );
            assert_eq!(status, S_UNSUPP);
            assert_eq!(used, 1);
            drop(client);
        }

        #[test]
        fn chain_without_status_descriptor_consumed_with_len_zero() {
            let (_dir, client, mut io) = spawn_volume_io();
            let mem = guest_mem();
            let (chain, addrs) = build_chain(&mem, &[(false, 16)]);
            mem.write_obj(header(VIRTIO_BLK_T_FLUSH, 0), addrs[0])
                .unwrap();
            assert_eq!(io.process_chain(&mem, chain), 0);
            drop(client);
        }

        #[test]
        fn config_space_capacity_and_blk_size() {
            let cfg = VirtioBlkConfig::for_volume(VOL_SIZE);
            assert_eq!({ cfg.capacity }, VOL_SIZE / SECTOR);
            assert_eq!({ cfg.blk_size }, BLOCK as u32);
            assert_eq!({ cfg.max_discard_seg }, 1);
            // get_config-style slicing round-trips through the raw bytes.
            let bytes = cfg.as_slice();
            assert_eq!(bytes.len(), std::mem::size_of::<VirtioBlkConfig>());
        }

        #[test]
        fn serial_truncates_long_ulid_basename() {
            let dir = std::path::PathBuf::from("/data/by_id/01ARZ3NDEKTSV4RRFFQ69G5FAV");
            let serial = serial_for_volume(&dir);
            assert_eq!(&serial, b"01ARZ3NDEKTSV4RRFFQ6");
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "vhost")))]
mod imp {
    use std::io;
    use std::path::Path;

    pub fn run_volume_vhost_blk(
        _dir: &Path,
        _size_bytes: u64,
        _socket: &Path,
        _fetch_inputs: crate::VolumeFetchInputs,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "vhost-user-blk transport requires Linux and the 'vhost' cargo feature",
        ))
    }
}

/// Serve a volume as a vhost-user-blk backend on `socket`. Blocks for
/// the lifetime of one frontend connection and returns when the VMM
/// disconnects.
pub fn run_volume_vhost_blk(
    dir: &Path,
    size_bytes: u64,
    socket: &Path,
    fetch_inputs: crate::VolumeFetchInputs,
) -> io::Result<()> {
    imp::run_volume_vhost_blk(dir, size_bytes, socket, fetch_inputs)
}
