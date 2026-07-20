//! The engine's LUKS leg: the resolver detects the `LUKS\xba\xbe` magic (byte
//! offset 0, shared by LUKS1 and LUKS2), constructs `luks::vfs::LuksLayer`, and —
//! with no credentials supplied — the layer surfaces a loud `NeedCredentials`
//! (ADR 0010).
//!
//! Fixture: a minimal synthetic LUKS1 header (magic + version 1) — enough to
//! route the resolver to the LUKS layer. The unlock needs a real volume +
//! passphrase (Tier-1, env-gated in `luks-forensic`); this drives the engine
//! detection/construction seam.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::{DynSource, ImageSource, VfsError, VfsResult};
use forensic_vfs_engine::Vfs;

/// Minimal in-memory ImageSource over an owned buffer.
struct Mem(Vec<u8>);
impl ImageSource for Mem {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        let Some(src) = self.0.get(off..) else {
            return Ok(0);
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

/// A minimal LUKS1 header: the `LUKS\xba\xbe` magic at offset 0 and the on-disk
/// version `1` (big-endian u16 at offset 6). No other markers, so only the LUKS
/// prober claims it.
fn luks1_header() -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[0..6].copy_from_slice(&[0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe]); // "LUKS" + 0xBABE
    b[6..8].copy_from_slice(&1u16.to_be_bytes()); // version 1
    b
}

#[test]
fn vfs_routes_a_luks_magic_to_the_layer_and_demands_credentials() {
    let src: DynSource = Arc::new(Mem(luks1_header()));
    let result = Vfs::new().open_source(src);
    assert!(
        matches!(
            result,
            Err(VfsError::NeedCredentials { scheme: "luks", .. })
        ),
        "engine should route to LUKS and demand credentials \
         (a signature-detected volume with no passphrase errs loud)"
    );
}
