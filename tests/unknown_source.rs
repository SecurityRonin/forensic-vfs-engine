//! Fail-loud vs degrade: a source no prober recognizes is a clean `fs: None`,
//! NOT an error — distinct from a bootstrap failure (which does error).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use forensic_vfs_engine::Vfs;

#[test]
fn unknown_source_yields_no_filesystem_not_an_error() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[0u8; 8192]).unwrap();
    f.flush().unwrap();

    let evidence = Vfs::new()
        .open(f.path())
        .expect("open must not error on unknown data");
    assert!(
        evidence.fs.is_none(),
        "a block of zeros is not a recognized filesystem or volume system"
    );
}

#[test]
fn missing_file_is_a_loud_error_not_silent_empty() {
    let r = Vfs::new().open(std::path::Path::new("/no/such/evidence.raw"));
    assert!(
        r.is_err(),
        "a missing base must fail loud, never a clean empty"
    );
}
