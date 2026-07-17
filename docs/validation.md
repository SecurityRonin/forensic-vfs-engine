# Validation

The engine is a thin resolver over the fleet readers; each reader owns its own
Tier-1 validation (differential vs. The Sleuth Kit / `qemu-img` / `hdiutil` /
`pyewf` on real artifacts, documented in that reader's repo). The engine's own
tests prove the **detection + mount + walk** path end-to-end against real,
oracle-validated fixtures — that the right reader is selected for each stack and
that the mounted filesystem surfaces the known ground-truth file.

## End-to-end fixtures

Every fixture under `tests/data/` is either a real artifact copied from a reader
repo (carrying that repo's oracle) or a Tier-2 self-minted image with its mint
command recorded in [`tests/data/README.md`](https://github.com/SecurityRonin/forensic-vfs-engine/blob/main/tests/data/README.md).

| Test | Stack exercised | Ground truth |
|---|---|---|
| `open_ntfs_e01` | EWF → NTFS | root file present |
| `open_partitioned` | EWF → MBR → NTFS | volume resolved |
| `open_gpt` | EWF → GPT → NTFS | volume resolved |
| `open_ext4` | raw → ext4 | `hello.txt` (TSK: inode 13) |
| `open_xfs` | raw → XFS | real XFS volume walked |
| `open_iso` | raw → ISO 9660 | PVD `CD001` |
| `open_apfs` | raw → APFS | real APFS content |
| `open_hfs` | raw → HFS+ | TSK-oracle volume |
| `open_fat` / `open_exfat` | raw → FAT / exFAT | `HELLO.TXT` (TSK) |
| `open_vhd` / `open_vhdx` / `open_vmdk` / `open_qcow2` | container → NTFS | NTFS payload |
| `open_dmg` | DMG (`koly`) → HFS+ | `HELLO.txt`; `hdiutil` sector count 3714 |
| `open_apm` | DMG → APM → HFS+ | partition-mapped payload |
| `open_aff4` | AFF4 (Zip) → ext4 | ext4 payload |
| `apfs_snapshots` | APFS `[H]` cohort | live-xid / snapshot ordering |
| `unknown_source` | unrecognized bytes | `fs: None`, missing file = loud error |
| `walk` | mounted tree enumeration | every fixture walkable |

## Robustness

The `fuzz_resolve` target feeds arbitrary bytes to `Vfs::open_source`; the
invariant is *resolving attacker-controllable disk bytes must never panic*. The
static partner is the panic-free lint posture (`unwrap_used`/`expect_used = deny`,
`unsafe_code = forbid`). Each reader additionally carries its own per-structure
fuzz targets in its repo.
