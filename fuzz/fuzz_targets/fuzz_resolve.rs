#![no_main]
//! The resolver parses attacker-controllable disk bytes (MBR/GPT tables,
//! filesystem boot sectors). Resolving arbitrary bytes must NEVER panic.

use std::sync::Arc;

use forensic_vfs::{DynSource, ImageSource, VfsResult};
use forensic_vfs_engine::Vfs;
use libfuzzer_sys::fuzz_target;

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

fuzz_target!(|data: &[u8]| {
    let src: DynSource = Arc::new(Mem(data.to_vec()));
    let _ = Vfs::new().open_source(src);
});
