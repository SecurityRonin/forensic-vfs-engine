# tests/data — forensic-vfs-engine fixtures

Both are minted from the TSK-validated `SampleTinyNtfsVolume` NTFS volume
(Joakim Schicht's `LogFileParser` sample, MIT; the raw `.dd` lives in
`ntfs-forensic/tests/data/SampleTinyNtfsVolume.zip`). Oracle for all content:
The Sleuth Kit (`file1.txt` = MFT record 37, 408 bytes, "Just some bogus").

| File | What | Mint |
|------|------|------|
| `ntfs_sample.E01` | bare 7 MiB NTFS volume, acquired | `ewfacquire -u -t ntfs_sample -f encase6 -c deflate:best partition.dd` (MD5 data `e4e9578a…`) |
| `partitioned_ntfs.E01` | 8 MiB MBR disk, one NTFS partition (type 0x07 @ LBA 2048), acquired | hand-built MBR + `dd` the volume at 1 MiB, then `ewfacquire` (MD5 data `b2f1cc81…`) |

The `partitioned_ntfs.dd` MBR was written in Python: partition entry at offset
446 (type 0x07, start LBA 2048, size 14336 sectors), signature 0x55AA at 510,
the NTFS volume copied to offset `2048*512`.

## ext4

`ext4.img` is a byte-for-byte copy of `ext4fs-forensic`'s TSK-validated
`minimal.img` (MD5 `966b3e52d95cb84679a973f43fd3702e`; provenance in
[`ext4fs-forensic/tests/data/README.md`](https://github.com/SecurityRonin/ext4fs-forensic)) —
a 4 MiB `mkfs.ext4` image (4096-byte blocks, no partition table) containing
`hello.txt` ("Hello, ext4!"). Oracle: The Sleuth Kit — `fls`/`istat`/`icat`
report `hello.txt` = **inode 13**, 12 bytes, direct block 9; used by
`open_ext4.rs` to prove the engine detects and mounts a bare ext4 volume.

## ISO 9660

`test.iso` (MD5 `e0f8babcd413a9a780481d9e086fc1a0`, 350 KiB) is a plain ISO 9660
volume (no Joliet/Rock Ridge) minted with `mkisofs`:

```
mkdir -p /tmp/isoroot && printf 'Hello, iso9660!' > /tmp/isoroot/hello.txt
mkisofs -o test.iso -V TESTVOL /tmp/isoroot
```

Oracle: The Sleuth Kit (`fsstat`/`fls`/`istat`/`icat -f iso9660`) — root directory
at **block 23**; `HELLO.TXT;1` = data extent **LBA 24**, **15 bytes**, `icat` →
`Hello, iso9660!`. Used by `open_iso.rs` to prove the engine's enlarged sniff
window sees the PVD at offset 32768 and mounts the volume via `Iso9660Probe`.

#### apfs_volume.bin / hfsplus_volume.bin
Copied from apfs-forensic/tests/data/apfs_content.bin (Tier-2 self-minted real APFS
carve, macOS shasum oracle) and hfsplus-forensic/tests/data/hfs_plus_volume.bin
(Tier-1, TSK-oracle-validated). Engine end-to-end resolution fixtures for ApfsProbe
(NXSB@32) and HfsPlusProbe (H+/HX@1024). Ground truth lives in the source repos.

## DMG (Apple UDIF)

`hfsplus.dmg` (MD5 `787b8b16bd9b58a115d22f3c867dbcb8`, ~8.8 KiB) is a Tier-2
self-minted UDIF disk image whose `koly` trailer sits at `file_len - 512`. It
wraps a **bare HFS+ volume** (no partition map), so the engine resolves it as
DMG container → HFS+ filesystem with no volume-system layer — exercising the
tail sniff window (`SniffWindow::has_magic_from_end(512, b"koly")`). Mint (macOS):

```
mkdir -p /tmp/vfssrc && printf 'forensic-vfs dmg fixture\n' > /tmp/vfssrc/HELLO.txt
hdiutil create -srcfolder /tmp/vfssrc -fs HFS+ -volname VFSHFS -layout NONE hfsplus.dmg
```

Oracle: `hdiutil imageinfo hfsplus.dmg` — **Sector Count 3714** (⇒ virtual disk
`3714 × 512 = 1,901,568` bytes, matched by `DmgReader::virtual_disk_size()`); the
root HFS+ directory holds `HELLO.txt`. Used by `open_dmg.rs`.

## AFF4

`ext4.aff4` (MD5 `f56dca10d6faaf7d0ecc996c1848dfa9`, ~18 KiB) wraps the
TSK-validated `ext4.img` **byte-for-byte** as a direct `aff4:ImageStream`
(512-byte chunks, `aff4:NullCompressor`, Deflate-stored in the Zip so the
mostly-zero image compresses to ~18 KiB). It exercises the AFF4 (`PK\x03\x04` →
`Maybe`) container leg. Minted with a throwaway generator that mirrors
`aff4-core`'s `testutil` ImageStream layout (stream ARN `aff4://issen-test-stream`,
bevy `issen-test-stream/00000000` + `.index`); no `pyaff4`/`aff4imager` was needed.

Oracle (two tiers): (1) `aff4-core`'s own reader reconstructs the virtual disk
**byte-identically** to `ext4.img` (`virtual_disk_size` = 4,194,304); (2) The
Sleuth Kit on that ext4 image — `hello.txt` = **inode 13**, 12 bytes,
"Hello, ext4!" (see the ext4 entry above). Used by `open_aff4.rs`.

## UDF

`udf.img` (MD5 `31d06a9942f8bc4983617631a9ac4e30`, 8 MiB) is a byte-for-byte copy
of `udf-forensic`'s `udf_plain.img`, a bare **UDF 1.50** volume authored by
`mkudffs` (udftools 2.3) for CD-R media (provenance in
[`udf-forensic/tests/data/README.md`](https://github.com/SecurityRonin/udf-forensic);
`mkudffs` output is freely redistributable — tool-authored structure, zero user
data). The Volume Recognition Sequence (`BEA01`/`NSR03`/`TEA01` at bytes
32768/34816/36864) sits inside the resolver's head window. Oracle: `udfinfo`
(source repo). Used by `open_udf.rs` to prove the engine detects and mounts a
bare UDF volume via `UdfProbe` → `udf_forensic::vfs::UdfVfs`.

## UFS2

`ufs.img` (MD5 `734455ec5b2f37db3a075a80f249a225`, 4,186,112 bytes) is the UFS2
filesystem **partition** extracted from `ufs-forensic`'s `ufs2.raw`
BSD-disklabel image at its partition base (byte 8192 = sector 16), re-based to
offset 0 so the UFS2 `fs_magic` (`0x19540119`) lands at absolute offset **66908**
inside the resolver's head window (the engine registers no BSD-disklabel volume
system, so the bare partition is what auto-detects). Extraction command:

```
dd if=ufs-forensic/tests/data/ufs2.raw of=ufs.img bs=512 skip=16
```

Source provenance (`newfs`-minted, Tier-1) in
[`ufs-forensic/tests/data/README.md`](https://github.com/SecurityRonin/ufs-forensic).
Oracle: The Sleuth Kit (`fls -o 16 -f ufs2 -r`) — root inode 2 holds
`passwords.txt`, `a_directory`, `a_link`, `.snap`. Used by `open_ufs.rs` to prove
the engine detects and mounts a bare UFS2 volume via `UfsProbe`, and that
`open_all` falls back to the single filesystem for a bare volume.

## btrfs

No committed binary. `open_btrfs.rs` **assembles a walkable btrfs image
in-memory** (pure-Rust byte layout, no `mkfs`): an identity `sys_chunk_array`, a
ROOT_TREE leaf holding the FS_TREE ROOT_ITEM, and an FS_TREE leaf with a root
directory and an inline-extent file `note.txt`. The `_BHRfS_M` superblock magic
sits at byte 0x10040 (65600), inside the resolver's 128 KiB head window. The
builder is ported from `btrfs-forensic`'s own `core/src/vfs.rs` crafted-image
test (`walkable_image`) — the layout that repo verifies `BtrfsFs::open` accepts.
Since the engine only calls `BtrfsFs::open`, the same crafted image drives its
`BtrfsProbe` dispatch arm. Oracle: the `btrfs-forensic` crafted-image tests.
