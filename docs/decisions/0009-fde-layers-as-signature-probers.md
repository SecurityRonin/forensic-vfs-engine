# 9. Full-disk-encryption layers register as signature probers; decryption is deferred

Date: 2026-07-24
Status: Accepted

## Context

Evidence is frequently full-disk-encrypted (BitLocker, LUKS, FileVault/CoreStorage,
VeraCrypt/TrueCrypt). Detecting an encrypted volume and *unlocking* it are separate
concerns: detection is a byte-signature test the engine can do at resolve time,
while unlocking needs a credential (password / recovery key) the engine does not
hold, and the actual cryptography lives in each reader crate. The four FDE probers
were added in commit `2d36423` ("feat(engine): register BitLocker/LUKS/FileVault/
VeraCrypt FDE probers (0.1.4)").

## Decision

Register one `EncryptionOpen` prober per scheme in `default_openers`
(`src/lib.rs:326-330`); each `open` wraps the ciphertext in that reader's
`forensic_vfs::EncryptionLayer`, and the resolver's credential-attempt pass does
the decrypt-or-fall-through:

- **BitLocker** — `-FVE-FS-` at offset 3 ⇒ `Yes`; wraps
  `bitlocker::vfs::BitlockerLayer` (`src/lib.rs:1241-1261`).
- **LUKS** — `LUKS\xba\xbe` at offset 0 (shared by LUKS1/LUKS2) ⇒ `Yes`; the
  concrete version is resolved inside `LuksLayer`, so the prober declares the
  representative `Luks2` (`src/lib.rs:1268-1289`).
- **FileVault/CoreStorage** — `CS` at offset 88 ⇒ `Yes`; wraps `FileVaultLayer`
  (`src/lib.rs:1295-1317`).
- **VeraCrypt/TrueCrypt** — signature-less by design (the header is itself
  encrypted), so the prober can never claim more than `Confidence::Maybe`; only a
  credential attempt confirms it (`src/lib.rs:1324-1340`). This is a concrete case
  of the `Maybe`-then-open contract from ADR 0002.

Registration and signatures are pinned by
`default_openers_registers_the_four_encryption_layers` and
`encryption_probes_detect_their_signatures` (`src/lib.rs:1442-1508`).

## Consequences

- Detection of encrypted evidence is batteries-included (ADR 0003); the analyst
  sees the volume without configuring anything.
- Actual unlock requires a credential supplied to the resolver's credential pass —
  which is owned by `forensic-vfs-resolver`, not this engine (the code comment at
  `src/lib.rs:1320-1323` references that resolver's own ADR for the
  decrypt-or-fall-through behavior).
- A signature-less scheme (VeraCrypt) can only ever be a `Maybe`, so it is
  attempted last and confirmed solely by a successful credentialed open.
