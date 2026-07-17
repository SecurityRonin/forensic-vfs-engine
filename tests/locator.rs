//! `Evidence.root` records the detected layer stack as a `PathSpec` locator — so
//! a finding can cite, and a session re-open, the exact resolved stack (not just
//! the base path). Verified via the lossless canonical URI.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::Vfs;

fn open_uri(img: &str) -> String {
    let path = format!("{}/tests/data/{img}", env!("CARGO_MANIFEST_DIR"));
    Vfs::new().open(Path::new(&path)).unwrap().root.to_uri()
}

#[test]
fn evidence_locator_records_the_detected_stack() {
    // VHD container -> NTFS: the locator names the container + filesystem layers.
    let vhd = open_uri("ntfs.vhd");
    assert!(vhd.contains("container:vhd"), "vhd locator: {vhd}");
    assert!(vhd.contains("fs:ntfs"), "vhd locator: {vhd}");

    // GPT disk (in E01) -> NTFS: the locator names the volume + filesystem layers.
    let gpt = open_uri("gpt_ntfs.E01");
    assert!(gpt.contains("volume:gpt"), "gpt locator: {gpt}");
    assert!(gpt.contains("fs:ntfs"), "gpt locator: {gpt}");
}
