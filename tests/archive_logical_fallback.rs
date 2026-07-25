//! ADR-0014: `Vfs::open` surfaces **archive** (zip/7z/tar) and **logical**
//! (AD1/AFF4-Logical/DAR) containers as a browsable `forensic_vfs::FileSystem`,
//! so `Evidence.fs` is `Some(..)` for a loose-file container the disk/volume/
//! filesystem resolver declines (it has no raw sector stream underneath).
//!
//! The fixture is an uncompressed tar built with the third-party `tar` crate — a
//! deliberately *different* implementation than archive-core (which reads it back),
//! so the round-trip is an independent oracle, not a self-consistency check.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use forensic_vfs::{NodeKind, StreamId};
use forensic_vfs_engine::{walk, Vfs};

/// Build an uncompressed `ustar` archive: a top-level file plus a nested
/// subdirectory file, so the derived tree exercises the root, a synthesized
/// intermediate directory, and a nested leaf.
fn build_tar() -> Vec<u8> {
    fn add(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    }
    let mut b = tar::Builder::new(Vec::new());
    add(&mut b, "hello.txt", b"hello archive\n");
    add(&mut b, "sub/nested.txt", b"nested payload\n");
    b.into_inner().unwrap()
}

/// Write `bytes` to a temp file carrying `suffix` (so the name hint reaches the
/// archive sniffer) and return the handle (kept alive by the caller).
fn write_tmp(bytes: &[u8], suffix: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn archive_container_surfaces_a_browsable_filesystem() {
    let f = write_tmp(&build_tar(), ".tar");

    let ev = Vfs::new().open(f.path()).expect("open tar evidence");
    let fs = ev
        .fs
        .expect("a loose-file tar archive must surface as a browsable FileSystem (ADR-0014)");

    // The root directory lists the top-level file and the nested subdirectory.
    let root = fs.root();
    let names: Vec<Vec<u8>> = fs
        .read_dir(root)
        .expect("read_dir root")
        .map(|e| e.expect("dir entry").name)
        .collect();
    assert!(names.iter().any(|n| n == b"hello.txt"), "root: {names:?}");
    assert!(names.iter().any(|n| n == b"sub"), "root: {names:?}");

    // Resolve the top-level file and read its bytes back verbatim.
    let hello = fs
        .lookup(root, b"hello.txt")
        .expect("lookup hello.txt")
        .expect("hello.txt present");
    assert_eq!(fs.meta(hello).expect("meta hello").kind, NodeKind::File);
    let mut buf = vec![0u8; 64];
    let n = fs
        .read_at(hello, StreamId::Default, 0, &mut buf)
        .expect("read hello.txt");
    assert_eq!(&buf[..n], b"hello archive\n");

    // Descend into the synthesized subdirectory and read the nested leaf.
    let sub = fs
        .lookup(root, b"sub")
        .expect("lookup sub")
        .expect("sub dir present");
    assert_eq!(fs.meta(sub).expect("meta sub").kind, NodeKind::Dir);
    let nested = fs
        .lookup(sub, b"nested.txt")
        .expect("lookup nested")
        .expect("nested.txt present");
    let mut nb = vec![0u8; 64];
    let n2 = fs
        .read_at(nested, StreamId::Default, 0, &mut nb)
        .expect("read nested.txt");
    assert_eq!(&nb[..n2], b"nested payload\n");

    // A full walk reaches both leaves through the derived tree.
    let all: Vec<String> = walk(fs.as_ref())
        .expect("walk archive")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).into_owned())
        })
        .collect();
    assert!(all.iter().any(|n| n == "hello.txt"), "walk: {all:?}");
    assert!(all.iter().any(|n| n == "nested.txt"), "walk: {all:?}");
}
