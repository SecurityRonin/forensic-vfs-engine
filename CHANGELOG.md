# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.10](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.9...forensic-vfs-engine-v0.1.10) - 2026-08-09

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored
- *(deps)* widen state-history-forensic to 0.2

## [0.1.9](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.8...forensic-vfs-engine-v0.1.9) - 2026-08-06

### Fixed

- *(security)* refresh the lock so lru reaches the patched line (RUSTSEC-2026-0002)

## [0.1.8](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.7...forensic-vfs-engine-v0.1.8) - 2026-08-04

### Added

- *(zfs)* GREEN — register ZFS in the openers registry

## [0.1.7](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.6...forensic-vfs-engine-v0.1.7) - 2026-07-26

### Fixed

- *(open)* route plain zip to the archive surface before the resolver's Aff4Decoder shadows it

## [0.1.6](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.5...forensic-vfs-engine-v0.1.6) - 2026-07-26

### Added

- surface archive + logical containers as browsable FileSystems (ADR-0014) ([#2](https://github.com/SecurityRonin/forensic-vfs-engine/pull/2))

## [0.1.5](https://github.com/SecurityRonin/forensic-vfs-engine/compare/forensic-vfs-engine-v0.1.4...forensic-vfs-engine-v0.1.5) - 2026-07-24

### Added

- *(open_all)* GREEN — surface every partition of a multi-partition disk

### Fixed

- *(open_all)* require valid partition table, reject FS boot sectors in MBR probe
- *(deps)* forensic-vfs 0.7 + Locator/Layer::File rename
- *(deps)* bump forensic-vfs 0.4->0.5 + resolver 0.1->0.2
# Changelog

All notable changes to `forensic-vfs-engine` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- release-plz appends new versions above this line, newest first. -->
