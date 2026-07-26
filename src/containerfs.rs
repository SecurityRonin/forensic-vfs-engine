//! ADR-0014 (deep path): archive (zip/7z/tar) and logical (AD1/AFF4-Logical/DAR)
//! containers surfaced as a browsable [`forensic_vfs::FileSystem`], using direct
//! standalone readers (no `disk-forensic`) so the engine keeps its low MSRV.
//!
//! These containers carry a *file tree*, not a raw sector stream, so the
//! disk/volume/filesystem resolver declines them and [`crate::Vfs::open`] would
//! otherwise yield `Evidence { fs: None }`. There are two shapes:
//!
//! - **AD1** — ad1-core ships its own forensic-vfs 0.7 adapter ([`ad1::Ad1Vfs`]),
//!   the engine's trait version, so it is mounted **directly** ([`open_ad1`]).
//! - **DAR and AFF4-Logical** — dar-core's adapter targets forensic-vfs 0.1 (a
//!   different major) and aff4 has none, so both expose a flat member list + a
//!   by-index/​by-key reader, composed into one synthetic-tree [`ContainerFs`]:
//!   a synthetic root (node 0) plus one node per member, wired parent→children by
//!   splitting each name on `/`, intermediate directories synthesized when a
//!   producer omits the record. Nodes are addressed by [`FileId::Opaque`] carrying
//!   an index into the node vector; a file node keeps its backing member index so
//!   [`FileSystem::read_at`] extracts it.
//!
//! The composed backend readers extract by `&mut self`, so each is wrapped in a
//! poison-recovering [`Mutex`] and one handle serves N workers; a per-node
//! decompressed-content cache inflates each member at most once.
//!
//! ## Mapping notes / limits (shared by the composed DAR/AFF4-Logical backends)
//! - **Times / ownership.** Neither backend API surfaces per-member MAC times or
//!   uid/gid/mode, so those [`FsMeta`] fields are honestly `None` — never a
//!   fabricated epoch.
//! - **Single stream.** A member has one data stream; a non-`Default`
//!   [`StreamId`] is refused loud.
//! - **Names are raw evidence.** Member names are surfaced verbatim; reads go
//!   through opaque node ids, never a path this adapter writes, so a zip-slip name
//!   cannot escape (nothing is extracted to disk).
//! - **Extents (first cut).** A container exposes no on-media runs, so
//!   [`FileSystem::extents`] yields one logical run per non-empty file.
//! - **Deleted / unallocated.** Container carving is not surfaced yet, so those
//!   streams are empty (future work, never fabricated data).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, DynFs, DynSource, ExtentStream,
    FileId, FileSystem, FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc,
    RunFlags, RunInfo, SectorSizes, SmallHex, StreamId, TimeZonePolicy, VfsError, VfsResult,
};

/// A neutral logical block size for a container byte stream (no media geometry).
const ARCHIVE_BLOCK: u32 = 512;

/// A backend that lists a flat set of members and extracts one by index. The
/// extract takes `&mut self`, which [`ContainerFs`] reconciles behind a `Mutex`.
trait Members: Send {
    /// The fully-decompressed bytes of member `index`, or a loud error.
    fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>>;
}

/// One flat member as listed by a backend: its `/`-separated name, size, whether
/// it names a directory, and the backend index used to extract it.
struct Flat {
    name: String,
    size: u64,
    is_dir: bool,
    index: usize,
}

/// One node in the derived directory tree. The synthetic root is node 0
/// (`entry_idx` `None`); every listed member becomes a node, plus any intermediate
/// directory implied by a path but not itself listed (`entry_idx` `None`).
struct Node {
    /// Backend member index; `None` for the synthetic root and for intermediate
    /// directories implied by a path but not themselves listed.
    entry_idx: Option<usize>,
    /// Last path component (raw bytes) — the name a parent lists this child under.
    name: Vec<u8>,
    kind: NodeKind,
    size: u64,
    /// Node ids of this node's directory children.
    children: Vec<u64>,
}

/// Backend reader plus its per-node decompressed-content cache, under one mutex.
struct Inner<R: Members> {
    reader: R,
    /// Node id → the member's fully-decompressed bytes (extraction is not free,
    /// and `read_at` may be called repeatedly at different offsets).
    cache: HashMap<u64, Arc<Vec<u8>>>,
}

/// A mounted container (archive or logical) exposed through the forensic-vfs
/// `FileSystem` contract. Reads are `&self` over an interior `Mutex`, so one
/// handle serves N workers.
struct ContainerFs<R: Members> {
    inner: Mutex<Inner<R>>,
    nodes: Vec<Node>,
    kind: FsKind,
}

impl<R: Members> ContainerFs<R> {
    fn new(reader: R, nodes: Vec<Node>, kind: FsKind) -> Self {
        Self {
            inner: Mutex::new(Inner {
                reader,
                cache: HashMap::new(),
            }),
            nodes,
            kind,
        }
    }

    /// Lock the interior state, recovering from a poisoned mutex rather than
    /// panicking (Paranoid Gatekeeper).
    fn lock(&self) -> MutexGuard<'_, Inner<R>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve a [`FileId`] to a node, or a loud error for any non-`Opaque` id or
    /// an index outside the node table.
    fn node_of(&self, id: FileId) -> VfsResult<&Node> {
        let idx = index_of(id)?;
        self.nodes
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .ok_or(VfsError::Unsupported {
                layer: "container file-id",
                scheme: format!("Opaque({idx}) out of range"),
            })
    }

    /// The fully-decompressed bytes of node `node_id` (a file backed by member
    /// `entry_idx`), decoding once and caching by node id so repeated `read_at`
    /// offsets do not re-extract. A decode/IO failure is surfaced loud.
    fn content(&self, node_id: u64, entry_idx: usize) -> VfsResult<Arc<Vec<u8>>> {
        let mut inner = self.lock();
        if let Some(data) = inner.cache.get(&node_id) {
            return Ok(Arc::clone(data));
        }
        let bytes = inner.reader.read_member(entry_idx)?;
        let arc = Arc::new(bytes);
        inner.cache.insert(node_id, Arc::clone(&arc));
        Ok(arc)
    }
}

/// The node index carried by a [`FileId`]; any other identity domain is a caller
/// error surfaced loud.
fn index_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(n) => Ok(n),
        other => Err(VfsError::Unsupported {
            layer: "container file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// A container member exposes a single unnamed data stream; a named-stream id is
/// refused loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "container stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Derive the directory tree (node 0 = synthetic root) from the flat member list.
/// Each name is split on `/` (and `\`); intermediate directories are synthesized
/// on first use and deduplicated by their normalized path, so an explicit `sub/`
/// entry and an implied `sub` prefix resolve to one node.
fn build_tree(members: &[Flat]) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::with_capacity(members.len() + 1);
    // Node 0: synthetic root.
    nodes.push(Node {
        entry_idx: None,
        name: Vec::new(),
        kind: NodeKind::Dir,
        size: 0,
        children: Vec::new(),
    });

    // Normalized ('/'-joined, separator-trimmed) path -> node id. Root is "".
    let mut by_path: HashMap<String, u64> = HashMap::new();
    by_path.insert(String::new(), 0);

    for m in members {
        let comps: Vec<&str> = m
            .name
            .split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        let Some(last) = comps.len().checked_sub(1) else {
            continue; // a bare "/" (or empty) name addresses no node
        };

        let mut parent_id = 0u64;
        let mut acc = String::new();
        for (ci, comp) in comps.iter().enumerate() {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);

            if ci == last {
                // Leaf: the member itself (file, or an explicit directory record).
                if let Some(&existing) = by_path.get(&acc) {
                    // A directory implied earlier now has its explicit record;
                    // keep its identity, just attach the backing member.
                    let Some(n) = nodes.get_mut(usize::try_from(existing).unwrap_or(usize::MAX))
                    else {
                        continue; // cov:unreachable: by_path holds in-range node ids by construction
                    };
                    if n.entry_idx.is_none() {
                        n.entry_idx = Some(m.index);
                    }
                } else {
                    let id = nodes.len() as u64;
                    nodes.push(Node {
                        entry_idx: Some(m.index),
                        name: comp.as_bytes().to_vec(),
                        kind: if m.is_dir {
                            NodeKind::Dir
                        } else {
                            NodeKind::File
                        },
                        size: if m.is_dir { 0 } else { m.size },
                        children: Vec::new(),
                    });
                    by_path.insert(acc.clone(), id);
                    push_child(&mut nodes, parent_id, id);
                }
            } else if let Some(&existing) = by_path.get(&acc) {
                parent_id = existing;
            } else {
                let id = nodes.len() as u64;
                nodes.push(Node {
                    entry_idx: None,
                    name: comp.as_bytes().to_vec(),
                    kind: NodeKind::Dir,
                    size: 0,
                    children: Vec::new(),
                });
                by_path.insert(acc.clone(), id);
                push_child(&mut nodes, parent_id, id);
                parent_id = id;
            }
        }
    }
    nodes
}

/// Register `child` under `parent_id`'s children list.
fn push_child(nodes: &mut [Node], parent_id: u64, child: u64) {
    if let Some(parent) = nodes.get_mut(usize::try_from(parent_id).unwrap_or(usize::MAX)) {
        parent.children.push(child);
    }
}

impl<R: Members> FileSystem for ContainerFs<R> {
    fn kind(&self) -> FsKind {
        self.kind
    }

    fn root(&self) -> FileId {
        FileId::Opaque(0)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: ARCHIVE_BLOCK,
            physical: ARCHIVE_BLOCK,
            cluster_or_block: ARCHIVE_BLOCK,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // No per-member times are surfaced, so no anchoring is asserted.
        TimeZonePolicy::LocalUnknown
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let node = self.node_of(ino)?;
        if node.kind != NodeKind::Dir {
            return Err(not_a_dir(ino)?);
        }
        // Snapshot children into owned entries so the stream outlives the borrow.
        let mut out: Vec<VfsResult<VfsDirEntry>> = Vec::with_capacity(node.children.len());
        for &child in &node.children {
            let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) else {
                continue; // cov:unreachable: children hold in-range node ids by construction
            };
            out.push(Ok(VfsDirEntry {
                name: c.name.clone(),
                id: FileId::Opaque(child),
                kind: c.kind,
            }));
        }
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let node = self.node_of(ino)?;
        require_default_stream(stream)?;
        // First cut: no on-media runs, so a non-empty file yields one logical run.
        if node.size == 0 {
            return Ok(ExtentStream::empty());
        }
        let run = RunInfo {
            run: ByteRun {
                image_offset: 0,
                len: node.size,
                flags: RunFlags::default(),
            },
            alloc: RunAlloc::Allocated,
        };
        Ok(ExtentStream::new(std::iter::once(Ok(run))))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let node = self.node_of(parent)?;
        if node.kind != NodeKind::Dir {
            return Err(not_a_dir(parent)?);
        }
        for &child in &node.children {
            let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) else {
                continue; // cov:unreachable: children hold in-range node ids by construction
            };
            if c.name == name {
                return Ok(Some(FileId::Opaque(child)));
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let idx = index_of(ino)?;
        let node = self.node_of(ino)?;
        Ok(FsMeta {
            ino: idx,
            kind: node.kind,
            allocated: Allocation::Allocated,
            size: node.size,
            nlink: 1,
            // No backend surfaces uid/gid/mode/times for a member.
            uid: None,
            gid: None,
            mode: None,
            times: MacbTimes::default(),
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let idx = index_of(ino)?;
        require_default_stream(stream)?;
        // Validate the node; a directory (or the root) has no extractable data.
        let (kind, entry_idx) = {
            let node = self.node_of(ino)?;
            (node.kind, node.entry_idx)
        };
        if kind != NodeKind::File {
            return Ok(0);
        }
        let Some(entry_idx) = entry_idx else {
            return Ok(0); // cov:unreachable: a File node always carries a backing member
        };
        let data = self.content(idx, entry_idx)?;
        let Ok(start) = usize::try_from(off) else {
            return Ok(0); // cov:unreachable: off is u64; usize::try_from only fails on <64-bit targets
        };
        if start >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - start).min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(start..start + n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    fn read_link(&self, ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // Validate the id (loud on a bad FileId); no backend surfaces link targets.
        self.node_of(ino)?;
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

/// A loud "not a directory" decode error for `read_dir`/`lookup` on a file node.
fn not_a_dir(id: FileId) -> VfsResult<VfsError> {
    Ok(VfsError::Decode {
        layer: "container",
        offset: 0,
        detail: format!("node {:?} is not a directory", index_of(id)?),
        bytes: SmallHex::new(&[]),
    })
}

// --- Archive backend (zip / 7z / tar via archive-core) --------------------------

/// The `archive_core::Archive` reader as a [`Members`] backend.
struct ArchiveBackend(archive_core::Archive);

impl Members for ArchiveBackend {
    fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>> {
        self.0.read(index).map_err(|e| VfsError::Decode {
            layer: "archive",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })
    }
}

/// Map an `archive_core` format to the closest fleet [`FsKind`].
fn archive_kind(format: archive_core::Format) -> FsKind {
    match format {
        archive_core::Format::Zip => FsKind::ZIP,
        archive_core::Format::SevenZip => FsKind::from_name("7z"),
        // Tar / TarGz / TarBz2 and any other archive variant.
        _ => FsKind::from_name("tar"),
    }
}

/// Try to mount `base` as a browsable archive (zip/7z/tar). `Ok(None)` when the
/// bytes are not an archive — the fallback then tries the logical opener. `name`
/// is the file-name hint that distinguishes `.tgz`/`.tbz2` from a bare stream.
///
/// # Errors
/// A read error draining the source, or a loud [`VfsError::Decode`] when the bytes
/// sniff as an archive format but fail to parse (valid magic, corrupt body).
pub(crate) fn open_archive(base: &DynSource, name: Option<&str>) -> VfsResult<Option<DynFs>> {
    // archive-core reads the whole archive from an in-memory slice; drain the
    // source into a Vec (mirroring the crate's existing whole-source readers).
    let len = base.len();
    let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    let n = base.read_at(0, &mut bytes)?;
    bytes.truncate(n);

    let Some(archive) =
        archive_core::Archive::open(&bytes, name).map_err(|e| VfsError::Decode {
            layer: "archive",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })?
    else {
        return Ok(None);
    };

    let kind = archive_kind(archive.format());
    let members: Vec<Flat> = archive
        .entries()
        .iter()
        .enumerate()
        .map(|(index, e)| Flat {
            name: e.name.clone(),
            size: e.size,
            is_dir: e.is_dir,
            index,
        })
        .collect();
    let nodes = build_tree(&members);
    Ok(Some(Arc::new(ContainerFs::new(
        ArchiveBackend(archive),
        nodes,
        kind,
    ))))
}

// --- AD1 backend (ad1-core's native forensic-vfs 0.7 adapter) -------------------

/// Try to mount `path` as a browsable AD1 logical image (FTK Imager "Custom
/// Content Image"). ad1-core ships its own `forensic_vfs::FileSystem` adapter on
/// forensic-vfs 0.7 — the engine's version — so [`ad1::Ad1Vfs`] is returned
/// directly, with no synthetic-tree wrapper. `Ok(None)` when the file is not an
/// AD1: ad1-core maps its `NotAd1` signal to a bootstrap failure at the
/// `"ad1 mount"` stage, the "not this format" verdict, so it is declined cleanly.
///
/// # Errors
/// A loud [`VfsError`] for an AD1 that fails to parse — I/O, an unsupported
/// (e.g. encrypted) feature, or a malformed structure — never swallowed.
pub(crate) fn open_ad1(path: &Path) -> VfsResult<Option<DynFs>> {
    match ad1::Ad1Vfs::open(path) {
        Ok(fs) => Ok(Some(Arc::new(fs))),
        Err(VfsError::Bootstrap {
            stage: "ad1 mount", ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

// --- DAR backend (dar-core reader over the synthetic-tree ContainerFs) ----------

/// The `dar::DarReader` reader as a [`Members`] backend. dar-core's own
/// forensic-vfs adapter targets forensic-vfs 0.1 (a different major than the
/// engine's 0.7), so its `FileSystem` impl is not this engine's trait; the bare
/// reader is composed into the shared synthetic-tree [`ContainerFs`] instead.
/// DAR extracts by the byte-exact stored path, so each member index maps back to
/// its raw path key.
struct DarBackend {
    reader: dar::DarReader<std::fs::File>,
    /// Byte-exact stored paths, indexed parallel to the [`Flat`] member list.
    paths: Vec<Vec<u8>>,
}

impl Members for DarBackend {
    fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>> {
        // Clone the key so the `&self.paths` borrow ends before the `&mut` extract.
        let key = self
            .paths
            .get(index)
            .ok_or(VfsError::Unsupported {
                layer: "dar member",
                scheme: format!("index {index} out of range"),
            })?
            .clone();
        self.reader.extract(&key).map_err(|e| VfsError::Decode {
            layer: "dar",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })
    }
}

/// Try to mount `path` as a browsable DAR archive (Denis Corbin Disk ARchiver,
/// including the Passware variant). `Ok(None)` when the file is not a DAR
/// ([`dar::DarError::NotADar`] — the "not this format" verdict).
///
/// # Errors
/// A loud [`VfsError`] for a DAR that fails to open (I/O) or whose catalogue is
/// corrupt.
pub(crate) fn open_dar(path: &Path) -> VfsResult<Option<DynFs>> {
    let file = std::fs::File::open(path).map_err(|source| VfsError::Io {
        op: "dar open",
        source,
    })?;
    let reader = match dar::DarReader::open(file) {
        Ok(r) => r,
        Err(dar::DarError::NotADar) => return Ok(None),
        Err(e) => {
            return Err(VfsError::Decode {
                layer: "dar",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })
        }
    };
    // `entries()` returns an owned Vec, so the borrow ends before `reader` moves
    // into the backend. Keep the byte-exact path per index for extraction; the
    // tree name is the lossy-UTF-8 display form (DAR paths are not guaranteed
    // UTF-8), matching read-by-index so the extraction key stays byte-exact.
    let entries = reader.entries();
    let mut paths: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    let members: Vec<Flat> = entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            paths.push(e.path.clone());
            Flat {
                name: String::from_utf8_lossy(&e.path).into_owned(),
                size: e.size,
                is_dir: matches!(e.kind, dar::EntryKind::Directory),
                index,
            }
        })
        .collect();
    let nodes = build_tree(&members);
    Ok(Some(Arc::new(ContainerFs::new(
        DarBackend { reader, paths },
        nodes,
        FsKind::DAR,
    ))))
}

// --- AFF4-Logical backend (aff4:FileImage over the synthetic-tree ContainerFs) --

/// The `aff4::LogicalContainer` reader as a [`Members`] backend. aff4 has no
/// forensic-vfs adapter, so its flat file list is composed into the shared
/// synthetic-tree [`ContainerFs`]. `read_file` needs `&mut self` while
/// `files()` borrows `&self`, so the entry is cloned to release that borrow.
struct Aff4LogicalBackend(aff4::LogicalContainer);

impl Members for Aff4LogicalBackend {
    fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>> {
        let entry = self
            .0
            .files()
            .get(index)
            .ok_or(VfsError::Unsupported {
                layer: "aff4-logical member",
                scheme: format!("index {index} out of range"),
            })?
            .clone();
        self.0.read_file(&entry).map_err(|e| VfsError::Decode {
            layer: "aff4-logical",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })
    }
}

/// Try to mount `path` as a browsable AFF4-Logical (aff4:FileImage) container.
///
/// AFF4 is zip-based, so this is probed *ahead of* the sector-stream resolver and
/// the plain-archive reader (both mis-handle it: the physical AFF4 decoder errors
/// "no ImageStream", and a plain-zip reader would list the container's internal
/// turtle/segments instead of the captured files). `container_kind` classifies
/// the container from one turtle read.
///
/// `Ok(None)` for anything that is not an AFF4-Logical container: a non-AFF4 file
/// (`container_kind` errors), a physical disk AFF4, or an encrypted AFF4 — the
/// last two are left to the resolver's physical decoder.
///
/// # Errors
/// A loud [`VfsError::Decode`] when the file *is* an AFF4-Logical container but
/// its metadata or segments fail to parse.
pub(crate) fn open_aff4_logical(path: &Path) -> VfsResult<Option<DynFs>> {
    match aff4::container_kind(path) {
        Ok(aff4::ContainerKind::Logical) => {}
        // Physical / encrypted AFF4 → the resolver's physical decoder; a non-AFF4
        // file makes container_kind error — decline cleanly either way.
        Ok(_) | Err(_) => return Ok(None),
    }
    let container = aff4::LogicalContainer::open(path).map_err(|e| VfsError::Decode {
        layer: "aff4-logical",
        offset: 0,
        detail: e.to_string(),
        bytes: SmallHex::new(&[]),
    })?;
    let members: Vec<Flat> = container
        .files()
        .iter()
        .enumerate()
        .map(|(index, e)| Flat {
            name: e.original_file_name.clone(),
            size: e.size,
            // AFF4-L records a flat file list with no directory nodes; the tree is
            // derived from the `/`-separated original file names.
            is_dir: false,
            index,
        })
        .collect();
    let nodes = build_tree(&members);
    Ok(Some(Arc::new(ContainerFs::new(
        Aff4LogicalBackend(container),
        nodes,
        FsKind::from_name("aff4"),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_vfs::{FileId, ImageSource};
    use std::io::Write;

    const DAR_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/loose.dar");

    /// A whole-image byte source over an in-memory buffer, for the archive openers
    /// (which drain the source into a Vec).
    struct Mem(Vec<u8>);
    impl ImageSource for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let o = usize::try_from(off).unwrap_or(usize::MAX).min(self.0.len());
            let s = &self.0[o..];
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            Ok(n)
        }
    }
    fn mem(b: Vec<u8>) -> DynSource {
        Arc::new(Mem(b))
    }

    /// Build a plain (Stored) zip in memory from `(name, bytes)` members.
    fn plain_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut c = std::io::Cursor::new(Vec::new());
        {
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let mut zw = zip::ZipWriter::new(&mut c);
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        c.into_inner()
    }

    /// A [`Members`] backend over an in-memory member table, with an optional
    /// index whose read fails (to exercise the content-decode error path).
    struct MockMembers {
        data: Vec<Vec<u8>>,
        fail_index: Option<usize>,
    }
    impl Members for MockMembers {
        fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>> {
            if Some(index) == self.fail_index {
                return Err(VfsError::Io {
                    op: "mock read",
                    source: std::io::Error::other("boom"),
                });
            }
            self.data
                .get(index)
                .cloned()
                .ok_or_else(|| VfsError::Unsupported {
                    layer: "mock",
                    scheme: format!("index {index} out of range"),
                })
        }
    }

    /// The canonical member list exercising every `build_tree` branch:
    /// a bare "/" (skipped), a top file, an explicit dir leaf, a child that
    /// reuses that dir as an intermediate, an implied dir later given its explicit
    /// record, and an empty file.
    fn sample_members() -> Vec<Flat> {
        vec![
            Flat {
                name: "/".into(),
                size: 0,
                is_dir: false,
                index: 0,
            },
            Flat {
                name: "top.txt".into(),
                size: 14,
                is_dir: false,
                index: 1,
            },
            Flat {
                name: "onlydir/".into(),
                size: 0,
                is_dir: true,
                index: 2,
            },
            Flat {
                name: "onlydir/inside.txt".into(),
                size: 6,
                is_dir: false,
                index: 3,
            },
            Flat {
                name: "imp/leaf.txt".into(),
                size: 4,
                is_dir: false,
                index: 4,
            },
            Flat {
                name: "imp".into(),
                size: 0,
                is_dir: true,
                index: 5,
            },
            Flat {
                name: "empty.dat".into(),
                size: 0,
                is_dir: false,
                index: 6,
            },
        ]
    }

    fn sample_fs(fail_index: Option<usize>) -> ContainerFs<MockMembers> {
        let members = sample_members();
        let nodes = build_tree(&members);
        let data = vec![
            Vec::new(),                  // 0: "/" (skipped)
            b"hello from mock".to_vec(), // 1: top.txt (15 bytes)
            Vec::new(),                  // 2: onlydir/
            b"inside".to_vec(),          // 3: inside.txt
            b"leaf".to_vec(),            // 4: leaf.txt
            Vec::new(),                  // 5: imp
            Vec::new(),                  // 6: empty.dat
        ];
        ContainerFs::new(
            MockMembers { data, fail_index },
            nodes,
            FsKind::from_name("mock"),
        )
    }

    fn child(fs: &ContainerFs<MockMembers>, parent: FileId, name: &[u8]) -> FileId {
        fs.lookup(parent, name).unwrap().unwrap()
    }

    #[test]
    fn container_fs_surface_and_arms() {
        let fs = sample_fs(None);
        let root = fs.root();
        assert_eq!(fs.kind(), FsKind::from_name("mock"));
        assert_eq!(root, FileId::Opaque(0));

        // Static descriptors.
        assert_eq!(fs.sector_sizes().logical, ARCHIVE_BLOCK);
        assert!(matches!(
            fs.timestamp_zone(),
            forensic_vfs::TimeZonePolicy::LocalUnknown
        ));

        // build_tree branches: the bare "/" name is skipped, so it is not a child.
        let root_names: Vec<Vec<u8>> = fs
            .read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().name)
            .collect();
        assert!(root_names.iter().any(|n| n == b"top.txt"));
        assert!(root_names.iter().any(|n| n == b"onlydir"));
        assert!(root_names.iter().any(|n| n == b"imp"));
        assert!(root_names.iter().any(|n| n == b"empty.dat"));

        // An implied intermediate reused by a later sibling (onlydir/inside.txt),
        // and an implied dir later given its explicit record (imp).
        let onlydir = child(&fs, root, b"onlydir");
        assert_eq!(fs.meta(onlydir).unwrap().kind, NodeKind::Dir);
        let inside = child(&fs, onlydir, b"inside.txt");
        assert_eq!(fs.meta(inside).unwrap().kind, NodeKind::File);
        let imp = child(&fs, root, b"imp");
        let _leaf = child(&fs, imp, b"leaf.txt");

        // extents: a non-empty file yields one run; an empty file yields none.
        let top = child(&fs, root, b"top.txt");
        let runs: Vec<_> = fs
            .extents(top, StreamId::Default)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(runs.len(), 1);
        let empty = child(&fs, root, b"empty.dat");
        assert_eq!(fs.extents(empty, StreamId::Default).unwrap().count(), 0);

        // read_at: happy read, then a second offset served from the content cache,
        // then a read past EOF, then a directory (no data).
        let mut buf = vec![0u8; 32];
        let n = fs.read_at(top, StreamId::Default, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from mock");
        let n2 = fs.read_at(top, StreamId::Default, 6, &mut buf).unwrap();
        assert_eq!(&buf[..n2], b"from mock");
        assert_eq!(
            fs.read_at(top, StreamId::Default, 9999, &mut buf).unwrap(),
            0
        );
        assert_eq!(
            fs.read_at(onlydir, StreamId::Default, 0, &mut buf).unwrap(),
            0
        );

        // read_link / deleted / unallocated: all empty by design, id validated.
        assert!(fs.read_link(top, 0).unwrap().is_empty());
        assert_eq!(fs.deleted().unwrap().count(), 0);
        assert_eq!(fs.unallocated().unwrap().count(), 0);

        // Error arms: a non-Opaque FileId, a named stream, not-a-directory, a miss.
        assert!(fs.meta(FileId::IsoExtent { block: 7 }).is_err());
        assert!(fs.read_at(top, StreamId::Slack, 0, &mut buf).is_err());
        assert!(fs.extents(top, StreamId::Named(1)).is_err());
        assert!(fs.read_dir(top).is_err());
        assert!(fs.lookup(top, b"x").is_err());
        assert!(fs.lookup(root, b"nope").unwrap().is_none());
    }

    #[test]
    fn content_error_propagates() {
        // A backend read failure surfaces from read_at (not swallowed).
        let fs = sample_fs(Some(1));
        let top = child(&fs, fs.root(), b"top.txt");
        assert!(fs
            .read_at(top, StreamId::Default, 0, &mut [0u8; 8])
            .is_err());

        // The mock's own out-of-range arm surfaces a loud error.
        let mut empty = MockMembers {
            data: Vec::new(),
            fail_index: None,
        };
        assert!(empty.read_member(5).is_err());
    }

    #[test]
    fn archive_kind_maps_each_format() {
        assert_eq!(archive_kind(archive_core::Format::Zip), FsKind::ZIP);
        assert_eq!(
            archive_kind(archive_core::Format::SevenZip),
            FsKind::from_name("7z")
        );
        assert_eq!(
            archive_kind(archive_core::Format::Tar),
            FsKind::from_name("tar")
        );
    }

    #[test]
    fn archive_backend_read_and_error() {
        let bytes = plain_zip(&[("a.txt", b"hi")]);
        let archive = archive_core::Archive::open(&bytes, Some("a.zip"))
            .unwrap()
            .unwrap();
        let mut backend = ArchiveBackend(archive);
        assert_eq!(backend.read_member(0).unwrap(), b"hi");
        // An out-of-range index surfaces a loud decode error.
        assert!(backend.read_member(9999).is_err());
    }

    #[test]
    fn open_archive_rejects_corrupt_zip() {
        // PK magic (so it sniffs as zip) but a truncated body: open must fail loud,
        // never return Ok(None).
        let corrupt = mem(b"PK\x03\x04corrupt-not-a-real-zip".to_vec());
        assert!(open_archive(&corrupt, Some("x.zip")).is_err());
    }

    #[test]
    fn open_aff4_logical_declines_a_plain_zip() {
        // A plain zip is not an AFF4 (container_kind errors) -> Ok(None), so the
        // resolver's archive layer handles it instead.
        let mut f = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        f.write_all(&plain_zip(&[("hello.txt", b"hi")])).unwrap();
        f.flush().unwrap();
        assert!(open_aff4_logical(f.path()).unwrap().is_none());
    }

    #[test]
    fn dar_backend_read_and_oob() {
        let file = std::fs::File::open(DAR_FIXTURE).unwrap();
        let reader = dar::DarReader::open(file).unwrap();
        let entries = reader.entries();
        let paths: Vec<Vec<u8>> = entries.iter().map(|e| e.path.clone()).collect();
        // Find a file member (not a directory) to extract.
        let file_idx = entries
            .iter()
            .position(|e| !matches!(e.kind, dar::EntryKind::Directory))
            .unwrap();
        let mut backend = DarBackend { reader, paths };
        assert!(backend.read_member(file_idx).is_ok());

        // An index past the path table surfaces a loud error.
        let reader2 = dar::DarReader::open(std::fs::File::open(DAR_FIXTURE).unwrap()).unwrap();
        let mut oob = DarBackend {
            reader: reader2,
            paths: Vec::new(),
        };
        assert!(oob.read_member(0).is_err());
    }

    #[test]
    fn open_dar_missing_file_is_io_error() {
        assert!(open_dar(Path::new("/nonexistent/definitely-not-here.dar")).is_err());
    }

    #[test]
    fn dar_backend_surfaces_an_extract_error() {
        // A path key absent from the archive fails extraction loud.
        let reader = dar::DarReader::open(std::fs::File::open(DAR_FIXTURE).unwrap()).unwrap();
        let mut backend = DarBackend {
            reader,
            paths: vec![b"no/such/member".to_vec()],
        };
        assert!(backend.read_member(0).is_err());
    }

    #[test]
    fn open_dar_surfaces_a_parse_error() {
        // A truncated DAR (magic intact, catalogue cut) is not the NotADar "not this
        // format" signal — it is a loud parse error, not a clean decline.
        let ok = std::fs::read(DAR_FIXTURE).unwrap();
        let mut f = tempfile::Builder::new().suffix(".dar").tempfile().unwrap();
        f.write_all(&ok[..64]).unwrap();
        f.flush().unwrap();
        assert!(open_dar(f.path()).is_err());
    }

    #[test]
    fn open_ad1_surfaces_a_parse_error() {
        // A truncated AD1 (header intact, body cut) is not the NotAd1 signal
        // (NotAd1 -> Bootstrap "ad1 mount" -> Ok(None)); it is a loud parse error.
        let built = ad1::testfix::build(ad1::testfix::sample_tree());
        let mut f = tempfile::Builder::new().suffix(".ad1").tempfile().unwrap();
        f.write_all(&built.bytes[..64]).unwrap();
        f.flush().unwrap();
        assert!(open_ad1(f.path()).is_err());
    }

    #[test]
    fn aff4_logical_read_error_propagates() {
        // Corrupt hello.txt's segment data (leaving information.turtle intact, so
        // container_kind stays Logical): the mount succeeds but reading the file
        // surfaces the segment CRC mismatch loud, never a silent short read.
        let ok = aff4::testutil::test_aff4_logical(
            "hello.txt",
            b"HELLO_AFF4_PAYLOAD_UNIQUE_MARKER",
            "00000000000000000000000000000000",
        );
        let marker = b"HELLO_AFF4_PAYLOAD_UNIQUE_MARKER";
        let pos = ok.windows(marker.len()).position(|w| w == marker).unwrap();
        let mut bytes = ok.clone();
        bytes[pos + 2] ^= 0xff;
        let mut f = tempfile::Builder::new().suffix(".aff4").tempfile().unwrap();
        f.write_all(&bytes).unwrap();
        f.flush().unwrap();

        let fs = open_aff4_logical(f.path()).unwrap().unwrap();
        let hello = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
        assert!(fs
            .read_at(hello, StreamId::Default, 0, &mut [0u8; 64])
            .is_err());
    }

    #[test]
    fn open_aff4_logical_surfaces_an_open_error() {
        // A Logical turtle whose referenced FileImage segment is absent: container_kind
        // classifies Logical (the turtle carries an aff4:FileImage), but the open
        // resolves no ZIP segment for it -> a loud decode error, not a clean decline.
        let ok = aff4::testutil::test_aff4_logical(
            "hello.txt",
            b"payload",
            "00000000000000000000000000000000",
        );
        // Rebuild a zip carrying ONLY the verbatim turtle, dropping the segment it
        // references, so resolve_segment fails inside LogicalContainer::open.
        let turtle = {
            let mut za = zip::ZipArchive::new(std::io::Cursor::new(ok)).unwrap();
            let mut e = za.by_name("information.turtle").unwrap();
            let mut s = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut s).unwrap();
            s
        };
        let mut c = std::io::Cursor::new(Vec::new());
        {
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let mut zw = zip::ZipWriter::new(&mut c);
            zw.start_file("information.turtle", opts).unwrap();
            zw.write_all(&turtle).unwrap();
            zw.finish().unwrap();
        }
        let mut f = tempfile::Builder::new().suffix(".aff4").tempfile().unwrap();
        f.write_all(&c.into_inner()).unwrap();
        f.flush().unwrap();
        assert!(open_aff4_logical(f.path()).is_err());
    }
}
