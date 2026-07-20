//! The engine's BitLocker leg: the resolver detects the `-FVE-FS-` volume
//! signature (byte offset 3), constructs `bitlocker::vfs::BitlockerLayer`, and —
//! with no credentials supplied — the layer surfaces a loud `NeedCredentials`
//! rather than guessing (ADR 0010: a `Yes`-verdict encryption scheme is a
//! nameable, credential-gated condition, never a silent fall-through).
//!
//! Fixture: a minimal synthetic boot sector carrying only the `-FVE-FS-`
//! signature — enough to route the resolver to the BitLocker layer. The unlock
//! itself needs a real volume + key (Tier-1, env-gated in `bitlocker-forensic`);
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

/// A 512-byte boot sector with the BitLocker `-FVE-FS-` signature at offset 3 and
/// no other filesystem/volume/partition markers, so only the BitLocker prober
/// claims it.
fn bitlocker_boot_sector() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[3..11].copy_from_slice(b"-FVE-FS-");
    b
}

#[test]
fn vfs_routes_a_bitlocker_signature_to_the_layer_and_demands_credentials() {
    let src: DynSource = Arc::new(Mem(bitlocker_boot_sector()));
    let result = Vfs::new().open_source(src);
    assert!(
        matches!(
            result,
            Err(VfsError::NeedCredentials {
                scheme: "bitlocker",
                ..
            })
        ),
        "engine should route to BitLocker and demand credentials \
         (a signature-detected volume with no key errs loud)"
    );
}
