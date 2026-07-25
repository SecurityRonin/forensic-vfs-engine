//! ADR-0014: archive (zip/7z/tar) and logical (AD1/AFF4-Logical/DAR) containers
//! surfaced as a browsable [`forensic_vfs::FileSystem`].
//!
//! These containers carry a *file tree*, not a raw sector stream, so the
//! disk/volume/filesystem resolver declines them and [`crate::Vfs::open`] would
//! otherwise yield `Evidence { fs: None }`. Both backends expose the same shape —
//! a flat list of `/`-separated member names plus a by-index reader — so one
//! synthetic-tree [`ContainerFs`] serves both: a synthetic root (node 0) plus one
//! node per member, wired parent→children by splitting each name on `/`, with any
//! intermediate directory synthesized when a producer omits its record. Nodes are
//! addressed by [`FileId::Opaque`] carrying an index into the node vector; a file
//! node keeps its backing member index so [`FileSystem::read_at`] extracts it.
//!
//! The backend readers extract by `&mut self`, so each is wrapped in a
//! poison-recovering [`Mutex`] and one handle serves N workers; a per-node
//! decompressed-content cache inflates each member at most once.
//!
//! ## Mapping notes / limits (shared by both backends)
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
                    if let Some(n) = nodes.get_mut(usize::try_from(existing).unwrap_or(usize::MAX))
                    {
                        if n.entry_idx.is_none() {
                            n.entry_idx = Some(m.index);
                        }
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
            if let Some(c) = self.nodes.get(usize::try_from(child).unwrap_or(usize::MAX)) {
                if c.name == name {
                    return Ok(Some(FileId::Opaque(child)));
                }
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
            return Ok(0);
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

// --- Logical backend (AD1 / AFF4-Logical / DAR via disk-forensic) ---------------

/// The `disk_forensic::logical::LogicalImage` reader as a [`Members`] backend.
struct LogicalBackend(disk_forensic::logical::LogicalImage);

impl Members for LogicalBackend {
    fn read_member(&mut self, index: usize) -> VfsResult<Vec<u8>> {
        self.0.read_file(index).map_err(|e| VfsError::Decode {
            layer: "logical",
            offset: 0,
            detail: e.to_string(),
            bytes: SmallHex::new(&[]),
        })
    }
}

/// Map a logical container format to the closest fleet [`FsKind`].
fn logical_kind(format: disk_forensic::container::ContainerFormat) -> FsKind {
    use disk_forensic::container::ContainerFormat;
    match format {
        ContainerFormat::Ad1 => FsKind::AD1,
        ContainerFormat::Dar => FsKind::DAR,
        // Logical AFF4 (aff4:FileImage); no dedicated fleet FsKind.
        _ => FsKind::from_name("aff4"),
    }
}

/// Try to mount `path` as a browsable logical container (AD1/AFF4-Logical/DAR).
/// `Ok(None)` when the file is not a logical container ([`LogicalError::NotLogical`]).
///
/// # Errors
/// A loud [`VfsError::Decode`] when the file is a logical container that fails to
/// parse (corrupt/encrypted), or an I/O error opening it.
pub(crate) fn open_logical(path: &Path) -> VfsResult<Option<DynFs>> {
    let img = match disk_forensic::logical::open(path) {
        Ok(img) => img,
        Err(disk_forensic::logical::LogicalError::NotLogical(..)) => return Ok(None),
        Err(e) => {
            return Err(VfsError::Decode {
                layer: "logical",
                offset: 0,
                detail: e.to_string(),
                bytes: SmallHex::new(&[]),
            })
        }
    };

    let kind = logical_kind(img.format());
    let members: Vec<Flat> = img
        .entries()
        .iter()
        .enumerate()
        .map(|(index, e)| Flat {
            name: e.path.clone(),
            size: e.size,
            is_dir: e.is_dir,
            index,
        })
        .collect();
    let nodes = build_tree(&members);
    Ok(Some(Arc::new(ContainerFs::new(
        LogicalBackend(img),
        nodes,
        kind,
    ))))
}
