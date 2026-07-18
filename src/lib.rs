//! # forensic-vfs-engine
//!
//! The openers registry + resolver over the `forensic-vfs` contracts: one
//! [`Vfs::open`] that detects the container/volume/filesystem stack of a piece
//! of evidence and mounts a read-only `dyn FileSystem`. This is the
//! ORCHESTRATION crate — the one place that depends *down* on every fleet reader.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use forensic_vfs::adapters::{FileSource, SeekPoolSource, SourceCursor, SubRange};
use forensic_vfs::read::{le_u32, le_u64};
use forensic_vfs::{
    Confidence, ContainerFormat, ContainerOpen, DynFs, DynSource, FileId, FileSystem,
    FileSystemOpen, FsKind, FsMeta, Layer, NodeAddr, NodeKind, Openers, PathSpec, SmallHex,
    SnapshotRef, SniffWindow, VfsError, VfsResult, VolumeDesc, VolumeKind, VolumeScheme,
    VolumeSystem, VolumeSystemOpen,
};
use forensic_vfs_resolver::SourceOpen;
use state_history_forensic::epoch::EpochTag;

/// One resolved piece of evidence: its locator plus the mounted filesystem, when
/// the engine detected one (`None` for a source no registered prober recognized).
pub struct Evidence {
    /// The locator this evidence was opened from.
    pub root: PathSpec,
    /// The mounted read-only filesystem, if detected.
    pub fs: Option<DynFs>,
}

/// The engine handle: the reader openers plus the resolver.
pub struct Vfs {
    openers: Openers,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    /// A `Vfs` with every fleet reader registered ([`default_openers`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            openers: default_openers(),
        }
    }

    /// Open evidence at `path`: resolve the base byte source (an EWF container by
    /// path, or a raw file), then recurse container/volume/filesystem layers and
    /// mount the first filesystem found. A source nothing recognizes yields an
    /// `Evidence` with `fs: None` — a genuinely clean unknown, not an error.
    pub fn open(&self, path: &Path) -> VfsResult<Evidence> {
        let base = open_base(path)?;
        let base_spec = PathSpec::os(path);
        match self.openers.open(base, base_spec.clone(), 0)? {
            Some(r) => Ok(Evidence {
                root: r.spec,
                fs: Some(r.fs),
            }),
            None => Ok(Evidence {
                root: base_spec,
                fs: None,
            }),
        }
    }

    /// Resolve a filesystem directly from a byte source — an in-memory buffer, a
    /// nested image, or a carved region. `Ok(None)` when nothing recognizes it.
    pub fn open_source(&self, source: DynSource) -> VfsResult<Option<DynFs>> {
        let base = PathSpec::root(Layer::Range {
            start: 0,
            len: source.len(),
        });
        Ok(self.openers.open(source, base, 0)?.map(|r| r.fs))
    }

    /// Enumerate an APFS volume's snapshots as a time-indexed `[H]` cohort. The
    /// path is resolved through any container/volume-system nesting to its APFS
    /// filesystem (exactly as [`Vfs::open`] does), then apfs-core lists the
    /// snapshot-metadata tree. Evidence with no APFS filesystem yields an **empty**
    /// cohort — a genuinely clean "no APFS snapshots here", not an error.
    ///
    /// The returned cohort is a `Vec<SnapshotView>` (the list form of the richer
    /// `state_history_forensic::TemporalCohort<H>`, adopted here once the generic
    /// `HistoricalSource` wiring lands); each view carries an [`EpochTag`] derived
    /// from the snapshot's `create_time` and a re-openable [`PathSpec`] locator.
    ///
    /// # Errors
    /// The bootstrap/decoding errors of resolving the path, or an apfs-core decode
    /// failure while walking the snapshot-metadata tree.
    pub fn snapshots(&self, path: &Path) -> VfsResult<Vec<SnapshotView>> {
        let base = open_base(path)?;
        let base_spec = PathSpec::os(path);
        let Some(resolved) = self.openers.open(base, base_spec, 0)? else {
            return Ok(Vec::new());
        };
        if !is_apfs(&resolved.spec) {
            return Ok(Vec::new());
        }
        let source_spec = resolved.source_spec;
        let len = resolved.source.len();
        let cursor = SourceCursor::new(resolved.source, 0, len);
        let snaps = apfs_core::vfs::ApfsFs::snapshots(cursor).map_err(map_apfs_err)?;
        Ok(snaps
            .into_iter()
            .map(|s| snapshot_view(&source_spec, s.xid, s.name, s.create_time))
            .collect())
    }

    /// Re-mount one APFS snapshot by its transaction `xid` — the end-to-end
    /// counterpart to a [`SnapshotView`] locator. Resolves the path to its APFS
    /// filesystem, then mounts the volume state frozen at `xid` (the live volume
    /// for its own xid, else the retained snapshot). The returned [`Evidence`]
    /// carries the snapshot-topped locator and the mounted point-in-time
    /// filesystem.
    ///
    /// # Errors
    /// [`VfsError::Bootstrap`] if the path resolves to no filesystem;
    /// [`VfsError::Unsupported`] if the resolved filesystem is not APFS; or an
    /// apfs-core decode failure (including [`VfsError::Decode`] for an unknown
    /// `xid`).
    pub fn open_snapshot(&self, path: &Path, xid: u64) -> VfsResult<Evidence> {
        let base = open_base(path)?;
        let base_spec = PathSpec::os(path);
        let resolved = self
            .openers
            .open(base, base_spec, 0)?
            .ok_or(VfsError::Bootstrap {
                stage: "apfs snapshot",
                detail: "no filesystem detected in evidence".to_string(),
            })?;
        if !is_apfs(&resolved.spec) {
            return Err(VfsError::Unsupported {
                layer: "snapshot",
                scheme: "non-APFS filesystem has no APFS snapshot".to_string(),
            });
        }
        let source_spec = resolved.source_spec;
        let len = resolved.source.len();
        let cursor = SourceCursor::new(resolved.source, 0, len);
        let fs = apfs_core::vfs::ApfsFs::open_snapshot(cursor, xid).map_err(map_apfs_err)?;
        let root = source_spec
            .push(Layer::Snapshot {
                store: SnapshotRef::ApfsXid(xid),
            })
            .push(Layer::Fs {
                kind: FsKind::APFS,
                at: NodeAddr::Path(Vec::new()),
            });
        Ok(Evidence {
            root,
            fs: Some(Arc::new(fs)),
        })
    }
}

/// One snapshot of an APFS volume, viewed as a time-indexed state in the `[H]`
/// cohort: the wall-clock [`EpochTag`], the APFS transaction id, the snapshot
/// name, and a re-openable [`PathSpec`] locator (base ⇒ `Snapshot{ApfsXid}`).
#[derive(Debug, Clone)]
pub struct SnapshotView {
    /// Time-indexed identity, derived from the snapshot's `create_time`.
    pub epoch: EpochTag,
    /// The APFS snapshot transaction id.
    pub xid: u64,
    /// The snapshot name.
    pub name: String,
    /// A locator that [`Vfs::open_snapshot`] re-opens end-to-end.
    pub locator: PathSpec,
}

/// True when a resolved locator's top layer is an APFS filesystem.
fn is_apfs(spec: &PathSpec) -> bool {
    matches!(
        spec.layer,
        Layer::Fs {
            kind: FsKind::APFS,
            ..
        }
    )
}

/// Build a [`SnapshotView`] under `source_spec` (the APFS source's
/// pre-filesystem locator) from a snapshot's transaction id, name, and
/// `create_time`. Takes primitives rather than the `#[non_exhaustive]`
/// `apfs_core::snapshot::Snapshot` so the mapping is unit-testable directly.
fn snapshot_view(source_spec: &PathSpec, xid: u64, name: String, create_time: u64) -> SnapshotView {
    SnapshotView {
        epoch: epoch_from_create_time(create_time),
        xid,
        name,
        locator: source_spec.clone().push(Layer::Snapshot {
            store: SnapshotRef::ApfsXid(xid),
        }),
    }
}

/// Derive an [`EpochTag`] from an APFS snapshot `create_time` (nanoseconds since
/// 1970-01-01 UTC). The big-endian nanosecond timestamp occupies the low 8 bytes
/// (indices 24..32) of the 32-byte tag; the rest is zero. This is simple and
/// reversible — the timestamp round-trips back out of those 8 bytes — and orders
/// correctly: a later `create_time` yields a lexicographically greater tag.
fn epoch_from_create_time(create_time_ns: u64) -> EpochTag {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&create_time_ns.to_be_bytes());
    EpochTag::from_bytes(bytes)
}

/// Map an apfs-core error into a VFS decode error, keeping the original message.
// Used as a `.map_err(map_apfs_err)` adapter, so it must take the error by value.
#[allow(clippy::needless_pass_by_value)]
fn map_apfs_err(e: apfs_core::ApfsError) -> VfsError {
    VfsError::Decode {
        layer: "apfs snapshot",
        offset: 0,
        detail: e.to_string(),
        bytes: SmallHex::new(&[]),
    }
}

/// The fleet reader openers: filesystem probers + volume-system probers +
/// container decoders. Crypto (`EncryptionOpen`) and archive (`ArchiveOpen`)
/// layers register here as those readers grow their `vfs` features.
#[must_use]
pub fn default_openers() -> Openers {
    Openers::new()
        .filesystem(NtfsProbe)
        .filesystem(Ext4Probe)
        .filesystem(XfsProbe)
        .filesystem(Iso9660Probe)
        .filesystem(ApfsProbe)
        .filesystem(HfsPlusProbe)
        .filesystem(ExFatProbe)
        .filesystem(FatProbe)
        .volume_system(GptProbe)
        .volume_system(MbrProbe)
        .volume_system(ApmProbe)
        .container(VhdDecoder)
        .container(Qcow2Decoder)
        .container(VmdkDecoder)
        .container(VhdxDecoder)
        .container(DmgDecoder)
        .container(Aff4Decoder)
}

/// Resolve the base [`DynSource`] for a path. EWF is multi-segment and opens *by
/// path* (it discovers `.E02...` itself), so it is handled here rather than as a
/// single-stream `ContainerOpen`; everything else is a raw [`FileSource`].
fn open_base(path: &Path) -> VfsResult<DynSource> {
    if is_ewf(path) {
        let reader = ewf::EwfReader::open(path).map_err(|e| VfsError::Bootstrap {
            stage: "ewf::open",
            detail: e.to_string(),
        })?;
        Ok(Arc::new(reader))
    } else {
        Ok(Arc::new(FileSource::open(path)?))
    }
}

fn is_ewf(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("e01") || e.eq_ignore_ascii_case("ex01"))
}

/// NTFS filesystem prober: recognizes the `NTFS` OEM id and mounts `ntfs_core::NtfsFs`.
struct NtfsProbe;

impl FileSystemOpen for NtfsProbe {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // NTFS boot sector: OEM id "NTFS    " at byte offset 3.
        if w.has_magic(3, b"NTFS    ") {
            Confidence::Yes { how: "NTFS OEM id" }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = ntfs_core::NtfsFs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "ntfs",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// ext2/3/4 filesystem prober: recognizes the ext superblock magic and mounts
/// `ext4fs::Ext4Fs`.
struct Ext4Probe;

impl FileSystemOpen for Ext4Probe {
    fn kind(&self) -> FsKind {
        FsKind::EXT
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // The ext superblock sits at byte offset 1024; its `s_magic` (0xEF53,
        // little-endian) is at +0x38, i.e. absolute offset 1080.
        if w.has_magic(1080, &[0x53, 0xEF]) {
            Confidence::Yes {
                how: "ext2/3/4 superblock magic",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = ext4fs::Ext4Fs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "ext4",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// XFS filesystem prober: recognizes the `XFSB` superblock magic at byte 0 and
/// mounts `xfs::vfs::XfsFs`. XfsFs is slice-based, so `open` reads the whole
/// source into memory (see the xfs vfs adapter docs on the `&[u8]` bridge).
struct XfsProbe;

impl FileSystemOpen for XfsProbe {
    fn kind(&self) -> FsKind {
        FsKind::XFS
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        xfs::vfs::xfs_probe(w)
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        Ok(Arc::new(xfs::vfs::XfsFs::open(&src)?))
    }
}

/// ISO 9660 filesystem prober: recognizes the Primary Volume Descriptor and
/// mounts `iso::vfs::IsoVfs`. The PVD's `CD001` standard identifier sits at byte
/// offset 32769 (LBA 16, +1), so this needs the enlarged sniff window.
struct Iso9660Probe;

impl FileSystemOpen for Iso9660Probe {
    fn kind(&self) -> FsKind {
        FsKind::ISO9660
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // ECMA-119 §8.1: a Volume Descriptor at LBA 16 begins with the standard
        // identifier "CD001" at byte offset 32769 (32768 + 1 type byte).
        if w.has_magic(32769, b"CD001") {
            Confidence::Yes {
                how: "ISO 9660 CD001 volume descriptor",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = iso::vfs::IsoVfs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "iso9660",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// APFS container: the `nx_superblock` carries the magic `NXSB` at byte offset 32
/// (immediately after the 32-byte `obj_phys` object header) in block 0.
struct ApfsProbe;

impl FileSystemOpen for ApfsProbe {
    fn kind(&self) -> FsKind {
        FsKind::APFS
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(32, b"NXSB") {
            Confidence::Yes {
                how: "APFS NXSB container superblock",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = apfs_core::vfs::ApfsFs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "apfs",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// HFS+ / HFSX: the volume header sits at byte offset 1024 and begins with the
/// signature `H+` (`0x482B`) for HFS Plus or `HX` (`0x4858`) for HFSX.
struct HfsPlusProbe;

impl FileSystemOpen for HfsPlusProbe {
    fn kind(&self) -> FsKind {
        FsKind::HFS_PLUS
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        match w.at(1024, 2) {
            Some([0x48, 0x2B | 0x58]) => Confidence::Yes {
                how: "HFS+/HFSX volume header",
            },
            _ => Confidence::No,
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        // The HFS+ reader is slice-based, so the whole volume is read into a Vec.
        // No streaming path yet — a memory consideration for multi-GB volumes.
        let len = src.len();
        let mut volume = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        let n = src.read_at(0, &mut volume)?;
        volume.truncate(n);
        let fs = hfsplus::vfs::HfsFs::new(volume)?;
        Ok(Arc::new(fs))
    }
}

/// exFAT: the `EXFAT   ` identifier at byte offset 3 plus the `0x55AA` boot
/// signature. Registered before [`FatProbe`] because exFAT zeroes the legacy BPB
/// fields the FAT probe keys on.
struct ExFatProbe;

impl FileSystemOpen for ExFatProbe {
    fn kind(&self) -> FsKind {
        FsKind::EXFAT
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.at(510, 2) == Some(&[0x55, 0xaa]) && w.has_magic(3, b"EXFAT   ") {
            Confidence::Yes {
                how: "exFAT boot signature",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = fat::FatFs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "exfat",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// FAT12/16/32: a valid BPB — a jump instruction (`0xEB`/`0xE9`) at offset 0, a
/// power-of-two bytes-per-sector, and the `0x55AA` boot signature.
struct FatProbe;

impl FileSystemOpen for FatProbe {
    fn kind(&self) -> FsKind {
        FsKind::FAT
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.at(510, 2) != Some(&[0x55, 0xaa]) {
            return Confidence::No;
        }
        let jump = w.at(0, 1).and_then(|s| s.first().copied());
        let jump_ok = matches!(jump, Some(0xEB | 0xE9));
        let bps = w
            .at(11, 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map_or(0, u16::from_le_bytes);
        if jump_ok && bps.is_power_of_two() && (512..=4096).contains(&bps) {
            Confidence::Yes { how: "FAT BPB" }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynFs> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let fs = fat::FatFs::open(cursor).map_err(|e| VfsError::Decode {
            layer: "fat",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(Arc::new(fs))
    }
}

/// MBR (DOS) partition-table volume system: the classic 4-entry table at the end
/// of the boot sector. Extended partitions (types 0x05/0x0f) are not yet chased.
struct MbrProbe;

impl VolumeSystemOpen for MbrProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // 0x55AA boot signature plus at least one plausible partition entry.
        if w.at(510, 2) != Some(&[0x55, 0xaa]) {
            return Confidence::No;
        }
        let data = w.bytes();
        for i in 0..4usize {
            let base = 446 + i * 16;
            let ptype = data.get(base + 4).copied().unwrap_or(0);
            let size = le_u32(data, base + 12);
            if ptype != 0 && ptype != 0xEE && size != 0 {
                return Confidence::Yes {
                    how: "MBR partition table",
                };
            }
        }
        Confidence::No
    }

    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        Ok(Box::new(Mbr::parse(src)?))
    }
}

/// A parsed MBR: the parent source plus its primary partitions.
struct Mbr {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl Mbr {
    fn parse(src: DynSource) -> VfsResult<Self> {
        let mut sector = [0u8; 512];
        src.read_at(0, &mut sector)?;
        let mut volumes = Vec::new();
        for i in 0..4usize {
            let base = 446 + i * 16;
            let ptype = sector.get(base + 4).copied().unwrap_or(0);
            let start_lba = le_u32(&sector, base + 8);
            let size = le_u32(&sector, base + 12);
            if ptype == 0 || ptype == 0xEE || size == 0 {
                continue;
            }
            volumes.push(VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: u64::from(start_lba) * 512,
                len: u64::from(size) * 512,
                type_hint: Some(format!("0x{ptype:02x}")),
                label: None,
            });
        }
        Ok(Self {
            parent: src,
            volumes,
        })
    }
}

impl VolumeSystem for Mbr {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Mbr
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let desc = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "mbr volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(
            self.parent.clone(),
            desc.start,
            desc.len,
        )))
    }
}

/// GPT (GUID Partition Table) volume system: the `EFI PART` header at LBA 1 and
/// its partition-entry array. The protective MBR at LBA 0 is left to `MbrProbe`,
/// which ignores the 0xEE marker so GPT takes over.
struct GptProbe;

impl VolumeSystemOpen for GptProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // GPT header signature "EFI PART" at LBA 1 (byte offset 512).
        if w.has_magic(512, b"EFI PART") {
            Confidence::Yes {
                how: "GPT EFI PART header",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        Ok(Box::new(Gpt::parse(src)?))
    }
}

/// A parsed GPT: the parent source plus its partitions.
struct Gpt {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl Gpt {
    fn parse(src: DynSource) -> VfsResult<Self> {
        // The GPT primary header lives in LBA 1.
        let mut header = [0u8; 512];
        src.read_at(512, &mut header)?;
        if header.get(0..8) != Some(b"EFI PART".as_slice()) {
            return Err(VfsError::Decode {
                layer: "gpt",
                offset: 512,
                detail: "missing EFI PART signature".to_string(),
                bytes: SmallHex::new(header.get(0..8).unwrap_or(&[])),
            });
        }
        let entries_lba = le_u64(&header, 72);
        // Bomb guards: cap the entry count and size before allocating.
        let num_entries = le_u32(&header, 80).min(256) as usize;
        let entry_size = le_u32(&header, 84).clamp(128, 512) as usize;
        let array_len = num_entries.checked_mul(entry_size).unwrap_or(0);
        let mut arr = vec![0u8; array_len];
        src.read_at(entries_lba.saturating_mul(512), &mut arr)?;

        let mut volumes = Vec::new();
        for i in 0..num_entries {
            let Some(base) = i.checked_mul(entry_size) else {
                break; // cov:unreachable: num_entries<=256 & entry_size<=512 bound base
            };
            let Some(entry) = arr.get(base..base.saturating_add(entry_size)) else {
                break; // cov:unreachable: arr is sized num_entries*entry_size
            };
            // An all-zero type GUID marks an unused entry.
            let type_guid = entry.get(0..16).unwrap_or(&[]);
            if type_guid.iter().all(|&b| b == 0) {
                continue;
            }
            let first = le_u64(entry, 32);
            let last = le_u64(entry, 40);
            if last < first {
                continue;
            }
            let sectors = last - first + 1;
            volumes.push(VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: first.saturating_mul(512),
                len: sectors.saturating_mul(512),
                type_hint: Some(guid_hint(type_guid)),
                label: None,
            });
        }
        Ok(Self {
            parent: src,
            volumes,
        })
    }
}

impl VolumeSystem for Gpt {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let desc = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "gpt volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(
            self.parent.clone(),
            desc.start,
            desc.len,
        )))
    }
}

/// Apple Partition Map (APM): a Driver Descriptor Record (`ER`) in block 0 and a
/// chain of 512-byte partition-map entries (`PM`) from block 1. All big-endian.
struct ApmProbe;

impl VolumeSystemOpen for ApmProbe {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Apm
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // DDR 'ER' at block 0 and the first partition-map entry 'PM' at block 1
        // (512-byte blocks — the case for every fixed-disk APM).
        if w.has_magic(0, b"ER") && w.has_magic(512, b"PM") {
            Confidence::Yes {
                how: "Apple Partition Map",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<Box<dyn VolumeSystem>> {
        Ok(Box::new(Apm::parse(src)?))
    }
}

struct Apm {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

/// Bytes read from the device start to parse the map (DDR + entries); covers 256
/// entries at a 512-byte block size with headroom.
const APM_MAP_CAP: u64 = 256 * 1024;

impl Apm {
    fn parse(src: DynSource) -> VfsResult<Self> {
        // The map (DDR + PM entries) lives at the device start; read a bounded
        // window and hand it to the fleet `apm-partition-core` reader.
        let cap = src.len().clamp(1, APM_MAP_CAP) as usize;
        let mut head = vec![0u8; cap];
        let n = src.read_at(0, &mut head)?;
        let map = apm::parse(head.get(..n).unwrap_or(&[])).ok_or_else(|| VfsError::Decode {
            layer: "apm",
            offset: 0,
            detail: "not an Apple Partition Map".to_string(),
            bytes: SmallHex::new(head.get(..2).unwrap_or(&[])),
        })?;

        let block_size = u64::from(map.block_size.max(1));
        let mut volumes = Vec::new();
        for (i, part) in map.partitions.iter().enumerate() {
            // Skip the map itself and free/unused space; keep data partitions.
            if part.type_name.eq_ignore_ascii_case("Apple_partition_map")
                || part.type_name.eq_ignore_ascii_case("Apple_Free")
                || part.type_name.eq_ignore_ascii_case("Apple_Void")
            {
                continue;
            }
            volumes.push(VolumeDesc {
                index: i,
                kind: VolumeKind::Partition,
                start: u64::from(part.start_block) * block_size,
                len: u64::from(part.block_count) * block_size,
                type_hint: Some(part.type_name.clone()),
                label: (!part.name.is_empty()).then(|| part.name.clone()),
            });
        }

        Ok(Self {
            parent: src,
            volumes,
        })
    }
}

impl VolumeSystem for Apm {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Apm
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let desc = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "apm volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(
            self.parent.clone(),
            desc.start,
            desc.len,
        )))
    }
}

fn guid_hint(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// VHD (Microsoft Virtual Hard Disk) container: a single-stream image with a
/// `conectix` footer. Decodes to its virtual disk stream via `vhd-core`.
struct VhdDecoder;

impl ContainerOpen for VhdDecoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Vhd
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // A dynamic/differencing VHD carries a footer copy ("conectix") at
        // offset 0; a fixed VHD has it only at the end (and its head sniffs as
        // the raw filesystem, so a filesystem prober handles that case).
        if w.has_magic(0, b"conectix") {
            Confidence::Yes {
                how: "VHD conectix footer",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let reader =
            vhd::VhdReader::open_reader(Box::new(cursor)).map_err(|e| VfsError::Decode {
                layer: "vhd",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// QCOW2 (QEMU Copy-On-Write v2) container: magic `QFI\xfb`. Decodes to its
/// virtual disk via `qcow2-core`.
struct Qcow2Decoder;

impl ContainerOpen for Qcow2Decoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Qcow2
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, &[0x51, 0x46, 0x49, 0xfb]) {
            Confidence::Yes { how: "QCOW2 magic" }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let reader =
            qcow2::Qcow2Reader::open_reader(Box::new(cursor)).map_err(|e| VfsError::Decode {
                layer: "qcow2",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// VMDK (VMware Virtual Disk) monolithic/sparse container: magic `KDMV`. Decodes
/// to its virtual disk via `vmdk-core` (multi-file flat extents are out of scope
/// for the single-stream decoder).
struct VmdkDecoder;

impl ContainerOpen for VmdkDecoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Vmdk
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // Sparse-extent magic "KDMV" at offset 0 (monolithicSparse / streamOptimized).
        if w.has_magic(0, b"KDMV") {
            Confidence::Yes {
                how: "VMDK KDMV magic",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let boxed: Box<dyn vmdk::ReadSeek + Send> = Box::new(cursor);
        let reader = vmdk::VmdkReader::open(boxed).map_err(|e| VfsError::Decode {
            layer: "vmdk",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// VHDX (Hyper-V v2) container: the file identifier `vhdxfile` sits at offset 0.
struct VhdxDecoder;

impl ContainerOpen for VhdxDecoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Vhdx
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, vhdx::FILE_MAGIC) {
            Confidence::Yes {
                how: "VHDX file magic",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let reader =
            vhdx::VhdxReader::open_reader(Box::new(cursor)).map_err(|e| VfsError::Decode {
                layer: "vhdx",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// DMG (Apple UDIF disk image) container: the `koly` trailer sits at the very
/// end of the file (`total_len - 512`), so this is a tail-probed decoder. Decodes
/// to its virtual disk stream via `dmg-core`.
struct DmgDecoder;

impl ContainerOpen for DmgDecoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Dmg
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        // UDIF footer: the 512-byte koly trailer begins at file_len - 512.
        if w.has_magic_from_end(512, b"koly") {
            Confidence::Yes {
                how: "DMG koly trailer",
            }
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let reader = dmg::DmgReader::open(cursor).map_err(|e| VfsError::Decode {
            layer: "dmg",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// AFF4 (Advanced Forensic Format 4) container: a Zip archive, so it sniffs only
/// as a `Maybe` on the `PK\x03\x04` local-file-header magic — `open` (via
/// `aff4-core`) disambiguates a real AFF4 from an unrelated Zip.
struct Aff4Decoder;

impl ContainerOpen for Aff4Decoder {
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Aff4
    }

    fn probe(&self, w: &SniffWindow) -> Confidence {
        if w.has_magic(0, &[0x50, 0x4b, 0x03, 0x04]) {
            Confidence::Maybe
        } else {
            Confidence::No
        }
    }

    fn open(&self, src: DynSource) -> VfsResult<DynSource> {
        let len = src.len();
        let cursor = SourceCursor::new(src, 0, len);
        let reader =
            aff4::Aff4Reader::open_reader(Box::new(cursor)).map_err(|e| VfsError::Decode {
                layer: "aff4",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })?;
        let vsize = reader.virtual_disk_size();
        Ok(Arc::new(SeekPoolSource::single(reader, vsize)))
    }
}

/// Cap on directory recursion depth in [`walk`] — a filesystem-loop guard.
const WALK_MAX_DEPTH: usize = 256;

/// One node found by [`walk`]: its path components (filesystem names are bytes,
/// not guaranteed UTF-8), its filesystem id, and its metadata.
pub struct WalkEntry {
    pub path: Vec<Vec<u8>>,
    pub id: FileId,
    pub meta: FsMeta,
}

/// Recursively enumerate every node of a mounted filesystem from the root — the
/// traversal a triage consumer runs over `Vfs::open(...).fs`. Depth-capped and
/// visited-guarded against directory loops; `.`/`..` self/parent entries are
/// skipped. Returns the nodes; a per-node read error aborts loud.
pub fn walk(fs: &dyn FileSystem) -> VfsResult<Vec<WalkEntry>> {
    let mut out = Vec::new();
    let mut visited: HashSet<FileId> = HashSet::new();
    let mut stack: Vec<(Vec<Vec<u8>>, FileId, usize)> = vec![(Vec::new(), fs.root(), 0)];
    while let Some((prefix, dir_id, depth)) = stack.pop() {
        if depth > WALK_MAX_DEPTH || !visited.insert(dir_id) {
            continue;
        }
        for entry in fs.read_dir(dir_id)? {
            let entry = entry?;
            if matches!(entry.name.as_slice(), b"." | b"..") {
                continue;
            }
            let mut path = prefix.clone();
            path.push(entry.name);
            let meta = fs.meta(entry.id)?;
            let is_dir = matches!(meta.kind, NodeKind::Dir);
            out.push(WalkEntry {
                path: path.clone(),
                id: entry.id,
                meta,
            });
            if is_dir {
                stack.push((path, entry.id, depth + 1));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_vfs::ImageSource;
    use std::io::Write;

    struct Mem(Vec<u8>);
    impl ImageSource for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let off = usize::try_from(offset).unwrap_or(usize::MAX);
            let Some(s) = self.0.get(off..) else {
                return Ok(0);
            };
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            Ok(n)
        }
    }
    fn mem(b: Vec<u8>) -> DynSource {
        Arc::new(Mem(b))
    }
    fn window(b: &[u8]) -> SniffWindow<'_> {
        SniffWindow::new(0, b)
    }

    #[test]
    fn default_openers_registers_btrfs_ufs_udf() {
        // The three new filesystem probers grow the registered set from 8 to 11
        // and expose the BTRFS/UFS/UDF kinds so the resolver can auto-detect them.
        let kinds: Vec<FsKind> = default_openers()
            .filesystems()
            .iter()
            .map(|p| p.kind())
            .collect();
        assert!(kinds.contains(&FsKind::BTRFS), "btrfs prober registered");
        assert!(kinds.contains(&FsKind::UFS), "ufs prober registered");
        assert!(kinds.contains(&FsKind::UDF), "udf prober registered");
        assert_eq!(kinds.len(), 11, "8 existing + 3 new filesystem probers");
    }

    #[test]
    fn default_is_new_and_probers_report_their_kinds() {
        let _ = Vfs::default().open_source(mem(vec![0u8; 64])).unwrap();
        assert_eq!(NtfsProbe.kind(), FsKind::NTFS);
        assert_eq!(MbrProbe.scheme(), VolumeScheme::Mbr);
        assert_eq!(GptProbe.scheme(), VolumeScheme::Gpt);
    }

    #[test]
    fn probers_say_no_on_unrecognized_bytes() {
        let empty = window(&[]);
        assert_eq!(NtfsProbe.probe(&empty), Confidence::No);
        assert_eq!(MbrProbe.probe(&empty), Confidence::No);
        assert_eq!(GptProbe.probe(&empty), Confidence::No);
        // 0x55AA present but only a 0xEE protective entry -> Mbr declines (GPT's job).
        let mut prot = vec![0u8; 512];
        prot[446 + 4] = 0xEE;
        prot[446 + 12] = 1; // non-zero size
        prot[510] = 0x55;
        prot[511] = 0xaa;
        assert_eq!(MbrProbe.probe(&window(&prot)), Confidence::No);
    }

    #[test]
    fn ntfs_magic_but_invalid_boot_is_a_loud_error() {
        // "NTFS    " at offset 3 makes NtfsProbe say Yes; the garbage then fails
        // NtfsFs::open -> Decode error propagates (never a silent None).
        let mut v = vec![0u8; 4096];
        v[3..11].copy_from_slice(b"NTFS    ");
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn a_garbage_e01_path_fails_loud() {
        let mut f = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
        f.write_all(b"not really an EWF image").unwrap();
        f.flush().unwrap();
        assert!(Vfs::new().open(f.path()).is_err());
    }

    #[test]
    fn gpt_parse_without_signature_errors_and_mbr_volume_index_is_bounded() {
        // Gpt::parse directly on bytes lacking EFI PART.
        assert!(Gpt::parse(mem(vec![0u8; 1024])).is_err());
        // A valid single-entry MBR; open_volume out of range errors.
        let mut d = vec![0u8; 512];
        d[446 + 4] = 0x07;
        d[446 + 8] = 1; // start LBA 1
        d[446 + 12] = 4; // size 4 sectors
        d[510] = 0x55;
        d[511] = 0xaa;
        let m = Mbr::parse(mem(d)).unwrap();
        assert_eq!(m.scheme(), VolumeScheme::Mbr);
        assert_eq!(m.volumes().len(), 1);
        assert!(m.open_volume(0).is_ok());
        assert!(m.open_volume(9).is_err());
    }

    #[test]
    fn apm_maps_partitions_and_errors_on_non_apm() {
        // A Driver Descriptor Map (block 0) with a 512-byte block size.
        let mut img = vec![0u8; 512];
        img[0..2].copy_from_slice(b"ER");
        img[2..4].copy_from_slice(&512u16.to_be_bytes()); // sbBlkSize
                                                          // A partition-map entry.
        let pm = |map_cnt: u32, pstart: u32, pcnt: u32, ptype: &str| {
            let mut e = vec![0u8; 512];
            e[0..2].copy_from_slice(b"PM");
            e[4..8].copy_from_slice(&map_cnt.to_be_bytes());
            e[8..12].copy_from_slice(&pstart.to_be_bytes());
            e[0x0c..0x10].copy_from_slice(&pcnt.to_be_bytes());
            e[0x30..0x30 + ptype.len()].copy_from_slice(ptype.as_bytes());
            e
        };
        // The map's own entry (skipped) + one Apple_HFS data partition.
        img.extend(pm(2, 1, 63, "Apple_partition_map"));
        img.extend(pm(2, 4, 2, "Apple_HFS"));
        img.extend(vec![0u8; 4 * 512]);

        let apm = Apm::parse(mem(img)).unwrap();
        assert_eq!(apm.scheme(), VolumeScheme::Apm);
        assert_eq!(apm.volumes().len(), 1); // Apple_partition_map is skipped
        assert_eq!(apm.volumes()[0].start, 4 * 512); // start_block 4 × 512
        assert!(apm.open_volume(0).is_ok());
        assert!(apm.open_volume(9).is_err());

        // No 'ER' signature -> apm-partition-core returns None -> loud Decode error.
        assert!(Apm::parse(mem(vec![0u8; 2048])).is_err());
    }

    #[test]
    fn recursion_is_depth_capped_on_a_self_referential_mbr() {
        // A partition covering the whole disk (start 0) recurses into itself; the
        // depth cap breaks it, yielding None rather than a stack overflow.
        let mut d = vec![0u8; 1024];
        d[446 + 4] = 0x83; // linux
                           // start LBA 0 (bytes stay 0), size 2 sectors
        d[446 + 12] = 2;
        d[510] = 0x55;
        d[511] = 0xaa;
        assert!(Vfs::new().open_source(mem(d)).unwrap().is_none());
    }

    #[test]
    fn container_decoders_report_format_and_error_on_bad_content() {
        assert_eq!(VhdDecoder.format(), ContainerFormat::Vhd);
        assert_eq!(Qcow2Decoder.format(), ContainerFormat::Qcow2);
        assert_eq!(VmdkDecoder.format(), ContainerFormat::Vmdk);
        assert_eq!(VhdxDecoder.format(), ContainerFormat::Vhdx);
        // Valid magic but garbage body -> the reader fails -> loud error, never
        // a silent None.
        let mut vhd = vec![0u8; 4096];
        vhd[0..8].copy_from_slice(b"conectix");
        assert!(Vfs::new().open_source(mem(vhd)).is_err());
        let mut q = vec![0u8; 4096];
        q[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        assert!(Vfs::new().open_source(mem(q)).is_err());
        let mut v = vec![0u8; 4096];
        v[0..4].copy_from_slice(b"KDMV");
        assert!(Vfs::new().open_source(mem(v)).is_err());
        let mut x = vec![0u8; 4096];
        x[0..8].copy_from_slice(vhdx::FILE_MAGIC);
        assert!(Vfs::new().open_source(mem(x)).is_err());
    }

    #[test]
    fn dmg_decoder_format_probe_and_open_error() {
        assert_eq!(DmgDecoder.format(), ContainerFormat::Dmg);
        // No koly trailer in the tail -> No (an all-zero window).
        assert_eq!(
            DmgDecoder.probe(&SniffWindow::with_tail(0, &[], 1024, &[0u8; 512])),
            Confidence::No
        );
        // koly at the tail (file_len - 512) makes the tail probe say Yes; an
        // xml plist region that overruns the file then fails DmgReader::open ->
        // loud error, never a silent None. koly starts at offset 512; its
        // xml_length field (koly+224) is set past the file end.
        let mut v = vec![0u8; 1024];
        v[512..516].copy_from_slice(b"koly");
        v[512 + 224..512 + 232].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn aff4_decoder_format_probe_and_open_error() {
        assert_eq!(Aff4Decoder.format(), ContainerFormat::Aff4);
        // No PK header -> No; a PK header -> Maybe (open disambiguates).
        assert_eq!(Aff4Decoder.probe(&window(&[])), Confidence::No);
        assert_eq!(
            Aff4Decoder.probe(&window(&[0x50, 0x4b, 0x03, 0x04])),
            Confidence::Maybe
        );
        // PK magic but not a valid AFF4 (garbage after the header) -> the reader
        // fails -> loud error, never a silent None.
        let mut v = vec![0u8; 256];
        v[0..4].copy_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn a_valid_container_holding_no_filesystem_resolves_to_none() {
        // An empty dynamic VHD decodes fine but its virtual disk is all zeros —
        // no filesystem inside, so the container loop falls through to None.
        let vhd = include_bytes!("../tests/data/empty.vhd").to_vec();
        assert!(Vfs::new().open_source(mem(vhd)).unwrap().is_none());
    }

    #[test]
    fn ext4_probe_kind_and_open_error() {
        assert_eq!(Ext4Probe.kind(), FsKind::EXT);
        // ext4 magic (0x53EF LE @ 1080) but an absurd s_log_block_size (@ 1048)
        // -> Ext4Fs::open rejects it -> loud error, never a silent None.
        let mut v = vec![0u8; 4096];
        v[1080] = 0x53;
        v[1081] = 0xef;
        v[1048..1052].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn iso9660_probe_kind_and_open_error() {
        assert_eq!(Iso9660Probe.kind(), FsKind::ISO9660);
        assert_eq!(Iso9660Probe.probe(&window(&[])), Confidence::No);
        // CD001 present at offset 32769 makes the probe say Yes; the surrounding
        // garbage then fails IsoVfs::open -> loud Decode error, never a silent None.
        let mut v = vec![0u8; 40 * 1024];
        v[32769..32774].copy_from_slice(b"CD001");
        assert_eq!(
            Iso9660Probe.probe(&window(&v)),
            Confidence::Yes {
                how: "ISO 9660 CD001 volume descriptor"
            }
        );
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn apfs_probe_kind_and_open_error() {
        assert_eq!(ApfsProbe.kind(), FsKind::APFS);
        assert_eq!(ApfsProbe.probe(&window(&[])), Confidence::No);
        // NXSB at offset 32 makes the probe say Yes; the surrounding garbage then
        // fails ApfsFs::open -> loud Decode error, never a silent None.
        let mut v = vec![0u8; 40 * 1024];
        v[32..36].copy_from_slice(b"NXSB");
        assert_eq!(
            ApfsProbe.probe(&window(&v)),
            Confidence::Yes {
                how: "APFS NXSB container superblock"
            }
        );
        assert!(Vfs::new().open_source(mem(v)).is_err());
    }

    #[test]
    fn hfsplus_probe_kind_and_no_on_short_window() {
        assert_eq!(HfsPlusProbe.kind(), FsKind::HFS_PLUS);
        // A window shorter than 1026 bytes cannot carry the @1024 signature.
        assert_eq!(HfsPlusProbe.probe(&window(&[])), Confidence::No);
        // HFSX signature 'HX' at 1024 is also accepted.
        let mut v = vec![0u8; 40 * 1024];
        v[1024..1026].copy_from_slice(&[0x48, 0x58]);
        assert_eq!(
            HfsPlusProbe.probe(&window(&v)),
            Confidence::Yes {
                how: "HFS+/HFSX volume header"
            }
        );
    }

    #[test]
    fn fat_and_exfat_magic_but_garbage_are_loud_errors() {
        // exFAT identifier + boot signature, but no valid structure -> loud error.
        let mut x = vec![0u8; 4096];
        x[3..11].copy_from_slice(b"EXFAT   ");
        x[510] = 0x55;
        x[511] = 0xaa;
        assert!(Vfs::new().open_source(mem(x)).is_err());

        // A plausible FAT BPB (jump + 512 bytes/sector + 0x55AA) over garbage ->
        // FatProbe says Yes, then FatFs::open fails loudly, never a silent None.
        let mut f = vec![0u8; 4096];
        f[0] = 0xEB;
        f[11..13].copy_from_slice(&512u16.to_le_bytes());
        f[510] = 0x55;
        f[511] = 0xaa;
        assert!(Vfs::new().open_source(mem(f)).is_err());
    }

    #[test]
    fn guid_hint_is_lowercase_hex() {
        assert_eq!(guid_hint(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn gpt_parse_skips_unused_and_reversed_entries() {
        let mut d = vec![0u8; 1280];
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA 2
        d[512 + 80..512 + 84].copy_from_slice(&2u32.to_le_bytes()); // num entries
        d[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
                                                                      // entry 0 @ 1024: valid basic-data partition, first 100 last 200
        d[1024] = 0xa2; // non-zero type GUID
        d[1024 + 32..1024 + 40].copy_from_slice(&100u64.to_le_bytes());
        d[1024 + 40..1024 + 48].copy_from_slice(&200u64.to_le_bytes());
        // entry 1 @ 1152: non-zero GUID but last<first -> skipped (continue)
        d[1152] = 0xa2;
        d[1152 + 32..1152 + 40].copy_from_slice(&500u64.to_le_bytes());
        d[1152 + 40..1152 + 48].copy_from_slice(&400u64.to_le_bytes());
        let g = Gpt::parse(mem(d)).unwrap();
        assert_eq!(g.scheme(), VolumeScheme::Gpt);
        assert_eq!(g.volumes().len(), 1, "reversed entry 1 is skipped");
        assert_eq!(g.volumes()[0].start, 100 * 512);
        assert!(g.open_volume(0).is_ok());
        assert!(g.open_volume(7).is_err());

        // test helper: a read starting past the end returns 0
        assert_eq!(Mem(vec![1, 2, 3]).read_at(99, &mut [0u8; 4]).unwrap(), 0);
    }

    // --- APFS snapshot cohort ([H] wiring) ---

    const APFS_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apfs_volume.bin");
    const EXT4_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ext4.img");

    /// The committed P4 fixture's live volume transaction id, resolved through the
    /// public apfs-core container API (the fixture has zero snapshots, so the live
    /// xid is the only mountable point in the timeline).
    fn apfs_live_xid() -> u64 {
        use std::io::{Read, Seek, SeekFrom};
        let bytes = std::fs::read(APFS_FIXTURE).unwrap();
        let mut c = apfs_core::ApfsContainer::open(std::io::Cursor::new(bytes)).unwrap();
        let bs = u64::from(c.superblock().block_size);
        let vaddr = c.volume_superblock_addrs().unwrap()[0];
        let mut r = c.into_reader();
        r.seek(SeekFrom::Start(vaddr * bs)).unwrap();
        let mut buf = vec![0u8; bs as usize];
        r.read_exact(&mut buf).unwrap();
        apfs_core::volume::ApfsVolume::parse(&buf).unwrap().xid()
    }

    fn zeros_file() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn epoch_from_create_time_round_trips_and_orders() {
        let t = 0x0123_4567_89ab_cdefu64;
        let tag = epoch_from_create_time(t);
        assert_eq!(&tag.0[0..24], &[0u8; 24], "high 24 bytes are zero");
        assert_eq!(
            u64::from_be_bytes(tag.0[24..32].try_into().unwrap()),
            t,
            "create_time round-trips out of the low 8 bytes"
        );
        assert!(
            epoch_from_create_time(t + 1).0 > tag.0,
            "a later create_time yields a greater tag"
        );
    }

    #[test]
    fn snapshot_view_carries_epoch_and_snapshot_locator() {
        let base = PathSpec::os("/ev.dmg");
        let v = snapshot_view(&base, 42, "daily".to_string(), 1000);
        assert_eq!(v.xid, 42);
        assert_eq!(v.name, "daily");
        assert_eq!(v.epoch, epoch_from_create_time(1000));
        assert!(matches!(
            v.locator.layer,
            Layer::Snapshot {
                store: SnapshotRef::ApfsXid(42)
            }
        ));
    }

    #[test]
    fn snapshots_on_unrecognized_source_is_empty() {
        let f = zeros_file();
        assert!(Vfs::new().snapshots(f.path()).unwrap().is_empty());
    }

    #[test]
    fn snapshots_on_non_apfs_filesystem_is_empty() {
        // ext4 mounts fine but is not APFS -> an empty cohort, never an error.
        assert!(Vfs::new()
            .snapshots(Path::new(EXT4_FIXTURE))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn open_snapshot_without_filesystem_is_bootstrap_error() {
        let f = zeros_file();
        assert!(matches!(
            Vfs::new().open_snapshot(f.path(), 1),
            Err(VfsError::Bootstrap { .. })
        ));
    }

    #[test]
    fn open_snapshot_on_non_apfs_is_unsupported() {
        assert!(matches!(
            Vfs::new().open_snapshot(Path::new(EXT4_FIXTURE), 1),
            Err(VfsError::Unsupported { .. })
        ));
    }

    #[test]
    fn open_snapshot_unknown_xid_is_a_loud_decode_error() {
        // A xid that is neither the live volume's nor a retained snapshot's ->
        // apfs-core SnapshotNotFound, surfaced as a VFS decode error.
        let bogus = apfs_live_xid().wrapping_add(0xDEAD_BEEF);
        assert!(matches!(
            Vfs::new().open_snapshot(Path::new(APFS_FIXTURE), bogus),
            Err(VfsError::Decode { .. })
        ));
    }

    #[test]
    fn open_snapshot_at_live_xid_mounts_and_walks() {
        let ev = Vfs::new()
            .open_snapshot(Path::new(APFS_FIXTURE), apfs_live_xid())
            .expect("open live-xid snapshot");
        let uri = ev.root.to_uri();
        assert!(
            uri.contains("snapshot:apfs") && uri.contains("fs:apfs"),
            "locator names the snapshot + APFS layers: {uri}"
        );
        let fs = ev.fs.expect("snapshot mounts a filesystem");
        let names: Vec<String> = walk(fs.as_ref())
            .unwrap()
            .into_iter()
            .filter_map(|e| {
                e.path
                    .last()
                    .map(|n| String::from_utf8_lossy(n).to_string())
            })
            .collect();
        assert!(names.iter().any(|n| n == "plain.txt"), "walk: {names:?}");
    }

    // --- golden: engine resolution == forensic_vfs_resolver::SourceOpen::open ---

    #[test]
    fn engine_resolution_matches_openers_open_directly() {
        // Driving resolution through the engine (`open_source`) yields the SAME
        // resolved filesystem as calling `Openers::open` (the resolver's
        // `SourceOpen`) directly on the same source. Both paths share the
        // resolver's one implementation; this pins that invariant so a future
        // divergence is caught by a failing test, not shipped silently.
        let bytes = std::fs::read(EXT4_FIXTURE).unwrap();
        let len = bytes.len() as u64;

        // Engine path.
        let via_engine = Vfs::new()
            .open_source(mem(bytes.clone()))
            .unwrap()
            .expect("engine resolves the ext4 fixture");

        // Direct Openers::open path, same default openers, same base spec.
        let base = PathSpec::root(Layer::Range { start: 0, len });
        let resolved = default_openers()
            .open(mem(bytes), base, 0)
            .unwrap()
            .expect("Openers::open resolves the ext4 fixture");

        // Same mounted filesystem identity: an identical walk of every node.
        let names = |fs: &dyn FileSystem| {
            let mut v: Vec<Vec<Vec<u8>>> = walk(fs).unwrap().into_iter().map(|e| e.path).collect();
            v.sort();
            v
        };
        assert_eq!(
            names(via_engine.as_ref()),
            names(resolved.fs.as_ref()),
            "engine and Openers::open mount the same filesystem"
        );
        // And the registry locator's top layer names the ext filesystem.
        assert!(
            matches!(
                resolved.spec.layer,
                Layer::Fs {
                    kind: FsKind::EXT,
                    ..
                }
            ),
            "registry resolved spec tops with fs:ext: {}",
            resolved.spec.to_uri()
        );
    }
}
