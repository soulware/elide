// ext4 scanning primitives for file-aware import.
//
// Parses the ext4 superblock, inode table, and extent tree to produce a
// list of `FileFragment` values describing every regular file's on-disk
// layout: the path, the file-relative byte offset of the fragment, the
// contiguous LBA range it occupies, and a hash of the fragment's bytes.
//
// Fragment = one contiguous LBA range owned by a file (one ext4 leaf
// extent, trimmed to the file's i_size). A file with N discontiguous
// ext4 extents produces N fragments.
//
// Hashes cover the full allocated block range (`lba_length * 4096`
// bytes) including any tail-block padding, so the fragment hash written
// to a segment entry equals the fragment hash written to the filemap —
// no split-brain between "storage hash" and "content hash". The
// filemap's separate `byte_count` column records the file-truthful
// byte count so downstream delta computation can cap the dictionary
// and compressed input at the real file length.
//
// Path joining uses the full-file hash trick: we hash each file's
// allocated blocks end-to-end as we walk the inode table, then walk
// the directory tree via ext4-view to map each file's path to its
// hash, then join the two on full-file hash. This avoids a second
// inode lookup and matches the approach used by the analysis tooling
// in src/extents.rs.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use ext4_view::{DirEntry, Ext4, Metadata, PathBuf as Ext4PathBuf};

const LBA_SIZE: u64 = 4096;
const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xef53;
const EXTENT_MAGIC: u16 = 0xf30a;
const INODE_FLAG_EXTENTS: u32 = 0x0008_0000;
const S_IFREG: u16 = 0x8000;
const S_IFMT: u16 = 0xf000;
const INCOMPAT_64BIT: u32 = 0x80;
const EXTENT_ENTRY_SIZE: usize = 12;

fn u16le(data: &[u8], off: usize) -> io::Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| io::Error::other("ext4: short read"))
}

fn u32le(data: &[u8], off: usize) -> io::Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| io::Error::other("ext4: short read"))
}

fn hilo64(hi: u32, lo: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

struct Superblock {
    block_size: u64,
    inode_size: usize,
    inodes_per_group: u32,
    num_block_groups: u32,
    is_64bit: bool,
}

impl Superblock {
    fn read(f: &mut File) -> io::Result<Self> {
        let mut buf = vec![0u8; 1024];
        f.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
        f.read_exact(&mut buf)?;

        if u16le(&buf, 0x38)? != EXT4_MAGIC {
            return Err(io::Error::other("not an ext4 image"));
        }

        let block_size = 1024u64 << u32le(&buf, 0x18)?;
        if block_size != LBA_SIZE {
            return Err(io::Error::other(format!(
                "unsupported ext4 block size: {block_size} (only 4096 supported)"
            )));
        }
        let inode_size = u16le(&buf, 0x58)? as usize;
        let inodes_per_group = u32le(&buf, 0x28)?;
        let blocks_per_group = u32le(&buf, 0x20)?;
        let first_data_block = u32le(&buf, 0x14)? as u64;
        let blocks_count = hilo64(u32le(&buf, 0x150)?, u32le(&buf, 0x04)?);
        let is_64bit = (u32le(&buf, 0x60)? & INCOMPAT_64BIT) != 0;

        let num_data_blocks = blocks_count.saturating_sub(first_data_block);
        let num_block_groups = num_data_blocks.div_ceil(blocks_per_group as u64) as u32;

        Ok(Self {
            block_size,
            inode_size,
            inodes_per_group,
            num_block_groups,
            is_64bit,
        })
    }

    fn bgdt_start(&self) -> u64 {
        // Block group descriptor table starts at block 1 (or 2 if block_size==1024).
        // We reject non-4096 block sizes in Superblock::read, so always block 1.
        self.block_size
    }

    fn bgd_size(&self) -> u64 {
        if self.is_64bit { 64 } else { 32 }
    }
}

fn inode_table_block(f: &mut File, sb: &Superblock, group: u32) -> io::Result<u64> {
    let offset = sb.bgdt_start() + group as u64 * sb.bgd_size();
    let mut buf = vec![0u8; sb.bgd_size() as usize];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut buf)?;

    let lo = u32le(&buf, 0x08)? as u64;
    let hi = if sb.is_64bit {
        u32le(&buf, 0x28)? as u64
    } else {
        0
    };
    Ok((hi << 32) | lo)
}

/// Walk an extent-tree node (`data` holds either the inode's 60-byte
/// embedded extent header + entries, or a full block for an index
/// node's child). Leaf extents are appended to `out` as
/// `(logical_block, phys_start_block, num_blocks)`.
fn collect_extents_with_logical(
    data: &[u8],
    f: &mut File,
    sb: &Superblock,
    out: &mut Vec<(u32, u64, u16)>,
) -> io::Result<()> {
    if data.len() < EXTENT_ENTRY_SIZE {
        return Ok(());
    }
    if u16le(data, 0)? != EXTENT_MAGIC {
        return Ok(());
    }

    let num_entries = u16le(data, 2)? as usize;
    let depth = u16le(data, 6)?;

    for i in 0..num_entries {
        let off = (i + 1) * EXTENT_ENTRY_SIZE;
        if off + EXTENT_ENTRY_SIZE > data.len() {
            break;
        }
        let entry = &data[off..off + EXTENT_ENTRY_SIZE];

        if depth == 0 {
            let logical = u32le(entry, 0)?;
            let len = u16le(entry, 4)? & 0x7fff; // strip uninitialised bit
            let phys = hilo64(u16le(entry, 6)? as u32, u32le(entry, 8)?);
            out.push((logical, phys, len));
        } else {
            let child = hilo64(u16le(entry, 8)? as u32, u32le(entry, 4)?);
            let mut child_data = vec![0u8; sb.block_size as usize];
            f.seek(SeekFrom::Start(child * sb.block_size))?;
            f.read_exact(&mut child_data)?;
            collect_extents_with_logical(&child_data, f, sb, out)?;
        }
    }

    Ok(())
}

/// One contiguous LBA range owned by a regular file.
///
/// `file_offset` is the byte offset within the file where this
/// fragment's data starts. `lba_start`/`lba_length` describe the
/// physical range. `byte_count` is the file-truthful number of bytes
/// in this fragment (≤ `lba_length * 4096`; smaller only for the last
/// fragment of a file whose size is not a multiple of 4096).
/// `hash` is `blake3(fragment_disk_bytes)` — i.e., over the full
/// `lba_length * 4096` bytes, *including* any tail-block padding.
pub struct FileFragment {
    pub path: String,
    pub file_offset: u64,
    pub lba_start: u64,
    pub lba_length: u32,
    pub byte_count: u64,
    pub hash: blake3::Hash,
    pub body: Vec<u8>,
}

struct InodeFragments {
    full_hash: blake3::Hash,
    fragments: Vec<PartialFragment>,
}

struct PartialFragment {
    file_offset: u64,
    lba_start: u64,
    lba_length: u32,
    byte_count: u64,
    hash: blake3::Hash,
    body: Vec<u8>,
}

/// Scan every regular-file inode in the ext4 image, returning per-inode
/// fragment lists. The full-file hash (blake3 of concatenated allocated
/// block data in logical order, truncated at i_size) is included so
/// callers can join this result with a path-indexed map from
/// `enumerate_file_paths`.
fn scan_inode_fragments(f: &mut File, sb: &Superblock) -> io::Result<Vec<InodeFragments>> {
    let mut results = Vec::new();
    let mut inode_buf = vec![0u8; sb.inode_size];

    for group in 0..sb.num_block_groups {
        let table_block = inode_table_block(f, sb, group)?;
        let table_offset = table_block * sb.block_size;

        for idx in 0..sb.inodes_per_group {
            let inode_offset = table_offset + idx as u64 * sb.inode_size as u64;
            f.seek(SeekFrom::Start(inode_offset))?;
            if f.read_exact(&mut inode_buf).is_err() {
                break;
            }

            let i_mode = u16le(&inode_buf, 0x00)?;
            if (i_mode & S_IFMT) != S_IFREG {
                continue;
            }
            if u16le(&inode_buf, 0x1a)? == 0 {
                continue;
            }
            let i_flags = u32le(&inode_buf, 0x20)?;
            if (i_flags & INODE_FLAG_EXTENTS) == 0 {
                continue;
            }
            let i_size = hilo64(u32le(&inode_buf, 0x6c)?, u32le(&inode_buf, 0x04)?);
            if i_size == 0 {
                continue;
            }

            let i_block = inode_buf[0x28..0x28 + 60].to_vec();
            let mut raw: Vec<(u32, u64, u16)> = Vec::new();
            collect_extents_with_logical(&i_block, f, sb, &mut raw)?;
            if raw.is_empty() {
                continue;
            }

            raw.sort_by_key(|&(logical, _, _)| logical);

            let mut full_hasher = blake3::Hasher::new();
            let mut fragments = Vec::new();
            let mut bytes_remaining = i_size;

            for (logical, phys_block, num_blocks) in raw {
                if bytes_remaining == 0 {
                    break;
                }
                let file_offset = logical as u64 * sb.block_size;
                if file_offset >= i_size {
                    // Preallocated extent beyond i_size — not real file data.
                    continue;
                }
                let allocated = num_blocks as u64 * sb.block_size;
                let byte_count = allocated.min(bytes_remaining);
                bytes_remaining = bytes_remaining.saturating_sub(byte_count);

                let disk_start = phys_block * sb.block_size;
                let mut body = vec![0u8; allocated as usize];
                f.seek(SeekFrom::Start(disk_start))?;
                f.read_exact(&mut body)?;

                // Fragment hash covers the full allocated region (with
                // padding); full-file hash covers only the file-truthful
                // bytes so callers can join on filemap path hashes
                // produced by enumerate_file_paths below.
                let fragment_hash = blake3::hash(&body);
                full_hasher.update(&body[..byte_count as usize]);

                fragments.push(PartialFragment {
                    file_offset,
                    lba_start: phys_block,
                    lba_length: num_blocks as u32,
                    byte_count,
                    hash: fragment_hash,
                    body,
                });
            }

            if fragments.is_empty() {
                continue;
            }

            results.push(InodeFragments {
                full_hash: full_hasher.finalize(),
                fragments,
            });
        }
    }

    Ok(results)
}

/// Walk the ext4 directory tree and return `(path → full_file_hash)`,
/// where `full_file_hash` is `blake3(ext4_view::read(path))` — i.e.,
/// blake3 of the file-truthful bytes.
fn enumerate_file_paths(image: &Path) -> io::Result<HashMap<blake3::Hash, Vec<String>>> {
    let fs = Ext4::load_from_path(image).map_err(|e| io::Error::other(e.to_string()))?;
    let mut out: HashMap<blake3::Hash, Vec<String>> = HashMap::new();
    let mut queue: Vec<Ext4PathBuf> = vec![Ext4PathBuf::new("/")];

    while let Some(dir) = queue.pop() {
        let entries = match fs.read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry: DirEntry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = entry.path();
            let metadata: Metadata = match fs.symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_dir() {
                queue.push(path);
            } else if metadata.file_type().is_regular_file() {
                let data = match fs.read(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let hash = blake3::hash(&data);
                if let Ok(s) = path.to_str() {
                    out.entry(hash).or_default().push(s.to_string());
                }
            }
        }
    }

    Ok(out)
}

/// Scan the ext4 image and return the flat list of file fragments,
/// together with a coverage bitset marking which LBAs are owned by
/// regular file data. Callers use the bitset to emit block-granular
/// DATA entries for metadata/directory/journal blocks (the ones with
/// a cleared bit) during import.
pub struct Ext4Scan {
    pub fragments: Vec<FileFragment>,
    pub file_lba_coverage: Vec<u64>, // bitset; bit i set → LBA i owned by a file fragment
    pub total_lbas: u64,
}

pub fn scan(image: &Path) -> io::Result<Ext4Scan> {
    let mut f = File::open(image)?;
    let image_size = f.metadata()?.len();
    if image_size % LBA_SIZE != 0 {
        return Err(io::Error::other("image size is not a multiple of 4096"));
    }
    let total_lbas = image_size / LBA_SIZE;

    let sb = Superblock::read(&mut f)?;
    let inodes = scan_inode_fragments(&mut f, &sb)?;
    let mut paths_by_hash = enumerate_file_paths(image)?;

    let mut fragments = Vec::new();
    let mut file_lba_coverage = vec![0u64; (total_lbas as usize).div_ceil(64)];

    for inode in inodes {
        let path = match paths_by_hash.get_mut(&inode.full_hash) {
            Some(paths) => match paths.pop() {
                Some(p) => p,
                None => continue, // all paths for this hash already consumed
            },
            None => continue, // orphan inode (deleted file still in table)
        };
        for part in inode.fragments {
            for i in 0..part.lba_length as u64 {
                let lba = part.lba_start + i;
                if lba < total_lbas {
                    let idx = (lba / 64) as usize;
                    let bit = lba % 64;
                    file_lba_coverage[idx] |= 1 << bit;
                }
            }
            fragments.push(FileFragment {
                path: path.clone(),
                file_offset: part.file_offset,
                lba_start: part.lba_start,
                lba_length: part.lba_length,
                byte_count: part.byte_count,
                hash: part.hash,
                body: part.body,
            });
        }
    }

    // Sort by LBA so the import loop can flush in physical order and
    // interleave metadata blocks (which are read block-by-block in LBA
    // order) with file fragments naturally.
    fragments.sort_by_key(|fr| fr.lba_start);

    Ok(Ext4Scan {
        fragments,
        file_lba_coverage,
        total_lbas,
    })
}

impl Ext4Scan {
    /// True if LBA `lba` is covered by any file fragment.
    pub fn lba_is_file(&self, lba: u64) -> bool {
        if lba >= self.total_lbas {
            return false;
        }
        let idx = (lba / 64) as usize;
        let bit = lba % 64;
        self.file_lba_coverage
            .get(idx)
            .is_some_and(|w| w & (1 << bit) != 0)
    }
}
