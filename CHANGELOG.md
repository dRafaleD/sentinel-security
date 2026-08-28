# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-28

### Added

- Sleuth Kit **bodyfile** export (`--output bodyfile`) for `mactime` / log2timeline compatibility
- File hashing via `--hash md5` or `--hash sha256` (live scans and TSK image reads)
- TSK `--include-deleted` for unallocated/orphan directory entries
- Extended `MacbRecord` metadata: mode, uid, gid, deleted flag, hashes
- TSK scan honors `--no-recursive` via `ScanOptions` depth logic

### Fixed

- Linux live scanner compiles against rustix 0.38 (`statx` / `CWD` API)
- TSK feature detects `tsk.pc` (Debian/Ubuntu) as well as `libtsk`
- TSK FFI matches the real libtsk C API (no invented getter symbols)
- NTFS scanner anomalies preserved through `annotate_records` merge
- `scan --sort timestamp` uses latest MACB timestamp
- Timeline MACB-specific sort filters event types correctly

## [0.1.0] - 2026-08-28

### Added

- Linux live filesystem scanner using `statx` with parallel `--jobs` workers
- MACB timestamp extraction (mtime, atime, ctime, btime) and chronological timeline view
- Anomaly detection rules: btime/mtime ordering, future timestamps, equal timestamps, zero epoch, ctime/mtime ordering, NTFS SI vs FN mismatch
- Output formats: table, JSON, CSV; write to stdout or `-o` / `--output-file`
- Scan filters: `--max-depth`, `--include` / `--exclude` globs, `--quiet`
- Time range filters: `--since` / `--until` (RFC 3339 or `YYYY-MM-DD`)
- Offline disk image support via libtsk (`--features tsk`): raw/dd, E01 multi-segment, AFF
- TSK partition handling: `--partition`, `--offset`, auto-detect offset, `--list-partitions`
- NTFS `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp inconsistency detection
- CLI subcommands: `scan` and `timeline`
- GitHub Actions CI (Linux with libtsk, Windows) and release workflow on `v*` tags
- Integration tests for FAT, MBR-partitioned, and NTFS images on Linux

### Fixed

- `annotate_records` now merges scanner-detected anomalies instead of overwriting them
- `scan --sort timestamp` sorts by latest available MACB timestamp, not mtime alone
- `timeline --sort mtime/atime/ctime/btime` filters to that MACB event type only
- Timeline `--min-severity` no longer hides clean events unless `--anomalies-only` is set

### Notes

- Live scanning is Linux-only by design; Windows/macOS compile with a stub scanner
- TSK support requires `libtsk` at build time (`--features tsk`)

[0.2.0]: #v020---2026-08-28
[0.1.0]: #v010---2026-08-28
