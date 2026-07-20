//! The engine's FileVault/CoreStorage leg: the resolver detects the CoreStorage
//! `CS` volume-header signature (byte offset 88), constructs
//! `filevault::vfs::FileVaultLayer`, and — with no credentials supplied — the
//! layer surfaces a loud `NeedCredentials` (ADR 0010).
//!
//! Fixture: a minimal synthetic CoreStorage volume header carrying only the `CS`
//! signature — enough to route the resolver to the FileVault layer. The unlock
//! needs a real volume + password (Tier-1, env-gated in `filevault-forensic`);
//! this drives the engine detection/construction seam.

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

/// A minimal CoreStorage volume header: the `CS` signature at offset 88 and no
/// other markers, so only the FileVault prober claims it.
fn corestorage_header() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[88..90].copy_from_slice(b"CS");
    b
}

#[test]
fn vfs_routes_a_corestorage_signature_to_the_layer_and_demands_credentials() {
    let src: DynSource = Arc::new(Mem(corestorage_header()));
    let result = Vfs::new().open_source(src);
    assert!(
        matches!(
            result,
            Err(VfsError::NeedCredentials {
                scheme: "filevault",
                ..
            })
        ),
        "engine should route to FileVault and demand credentials \
         (a signature-detected volume with no password errs loud)"
    );
}
