# macb-timeline

Linux-first forensic CLI for **MACB timestamp** collection, chronological timelines, and timestamp-anomaly detection.

Scan a live filesystem with `statx`, or open a disk image through The Sleuth Kit (`libtsk`). Export table, JSON, CSV, or Sleuth Kit **bodyfile** for `mactime` / log2timeline.

[![CI](https://github.com/dRafaleD/sentinel-security/actions/workflows/ci.yml/badge.svg)](https://github.com/dRafaleD/sentinel-security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Live scan** on Linux via `statx` (mtime, atime, ctime, btime) with optional parallel `--jobs`
- **Offline images** (`--features tsk`): raw/dd, E01 multi-segment, AFF when TSK is built with those backends
- **Partition handling**: `--partition`, `--offset`, auto-detect filesystem offset, `--list-partitions`
- **Anomaly rules** for timestomping indicators (including NTFS `$STANDARD_INFORMATION` vs `$FILE_NAME`)
- **Filters**: depth, include/exclude globs, `--since` / `--until`, `--anomalies-only`
- **Hashes**: `--hash md5` or `--hash sha256` on live files and TSK image reads
- **Deleted entries**: `--include-deleted` on TSK walks

## MACB on Linux

| Letter | Meaning | Source |
|--------|---------|--------|
| **M** | mtime — content modification | `stat` / `statx` |
| **A** | atime — last access | `stat` / `statx` |
| **C** | ctime — inode metadata change (**not** creation) | `stat` / `statx` |
| **B** | btime — birth / creation time | `statx` (ext4, xfs, btrfs, …) |

Missing `btime` is not treated as an anomaly; the column is `-` when the filesystem does not expose birth time. Comparisons ignore 1-second filesystem jitter.

## Build

Requires a recent [Rust](https://rustup.rs/) toolchain (edition 2021).

```bash
# Live scanning only
cargo build --release -p macb-timeline

# Offline disk image support (needs libtsk at build time)
cargo build --release -p macb-timeline --features tsk
```

### Linux packages

```bash
# Offline TSK support
sudo apt install sleuthkit libtsk-dev pkg-config

# Optional: E01/EWF and AFF if TSK was built with those libraries
sudo apt install libewf-dev libafflib-dev
```

Live scanning needs no extra packages beyond Rust.

### Platform support

| Platform | Live scan | TSK images |
|----------|-----------|------------|
| Linux | Full (`statx`) | When `--features tsk` and `libtsk` are available |
| Windows / macOS | Compiles; live scan is intentionally stubbed | Not typical (build without TSK) |

## Usage

```bash
# Table output (default)
macb-timeline scan /var/log

# JSON, sorted by latest MACB timestamp
macb-timeline scan /home/user --output json --sort timestamp

# Bodyfile for mactime / log2timeline
macb-timeline scan /var/log --output bodyfile -o bodyfile.txt

# Hash files while scanning
macb-timeline scan /evidence --hash sha256 --output json

# Anomalies only
macb-timeline scan /tmp --anomalies-only --min-severity high

# Parallel workers (0 = CPU count)
macb-timeline scan /var --jobs 8

# Depth and glob filters
macb-timeline scan /var/log --max-depth 3 --include "**/*.log" --exclude "**/*.gz" -o report.json --output json
```

### Timeline

```bash
macb-timeline timeline /etc --format table
macb-timeline timeline /var/log --format csv --anomalies-only
macb-timeline timeline /var/log --sort mtime
macb-timeline timeline /var/log --since 2024-01-01 --until 2024-01-31
```

`timeline --sort` defaults to chronological `timestamp` across all MACB types. `--sort mtime` (or `atime` / `ctime` / `btime`) keeps only that event type. `--min-severity` filters anomaly text unless `--anomalies-only` is set.

### Offline disk image (TSK)

Build with `--features tsk` and install `libtsk`.

```bash
macb-timeline scan --image /evidence/disk.dd --offset 0 --output json
macb-timeline scan --image /evidence/disk.raw --partition 2
macb-timeline scan --image /evidence/disk.raw
macb-timeline scan --image /evidence/disk.raw --list-partitions
macb-timeline scan --image /evidence/image.E01 --partition 1
macb-timeline scan --image /evidence/ntfs.raw --include-deleted --output json
```

## Anomaly rules

| Rule | Severity | Description |
|------|----------|-------------|
| `btime > mtime` | High | Creation after modification (timestomping) |
| `btime > atime` | Medium | Creation after access |
| `mtime` in future | High | Clock manipulation |
| `btime` in future | High | Clock manipulation |
| `ctime < mtime` | Medium | Metadata change before content change |
| All timestamps equal | Low | Possible anti-forensics |
| Zero epoch timestamps | Medium | Suspicious null timestamps |
| NTFS SI vs FN mismatch | High | `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps differ |

## CLI reference

### `scan`

| Flag | Default | Description |
|------|---------|-------------|
| `PATH` | required* | Live filesystem path |
| `--no-recursive` | recurse on | Disable directory recursion |
| `--follow-symlinks` | `false` | Follow symlinks (not recommended) |
| `--output` | `table` | `table`, `json`, `csv`, `bodyfile` |
| `--sort` | `mtime` | `timestamp`, `mtime`, `atime`, `ctime`, `btime`, `path` |
| `--anomalies-only` | `false` | Show only anomalous records |
| `--min-severity` | `info` | `info`, `low`, `medium`, `high` |
| `--jobs` | `0` | Parallel workers (`0` = CPU count) |
| `--max-depth` | — | Maximum directory depth (`0` = root only) |
| `--include` | — | Include glob (repeatable) |
| `--exclude` | — | Exclude glob (repeatable) |
| `--quiet` | `false` | Suppress progress and warnings on stderr |
| `-o` / `--output-file` | — | Write to file instead of stdout |
| `--since` / `--until` | — | RFC 3339 or `YYYY-MM-DD` |
| `--hash` | — | `md5` or `sha256` for regular files |
| `--include-deleted` | `false` | Deleted/unalloc TSK entries (image scans) |
| `--image` | — | Disk image path (TSK) |
| `--partition` | — | 1-based partition number (TSK) |
| `--offset` | — | Filesystem byte offset (TSK) |
| `--list-partitions` | `false` | List image partitions and exit (TSK) |

\* With TSK enabled, `PATH` is optional when `--image` is set.

### `timeline`

Same flags as `scan`, except `--output` is `--format`. `bodyfile` is only available on `scan`.

## Tests

```bash
cargo test -p macb-timeline
cargo test -p macb-timeline --features tsk   # Linux + libtsk: FAT, MBR, NTFS
```

CI runs on every push and pull request:

- **Linux**: tests with `--features tsk`, Clippy (`-D warnings`), release build
- **Windows**: unit tests and release build (live-scan stub)

Tag pushes matching `v*` build Linux (TSK) and Windows binaries and attach them to a GitHub Release.

## Project layout

```
crates/macb-timeline/
├── src/
│   ├── lib.rs / main.rs / cli.rs
│   ├── anomalies.rs / timeline.rs / time_filter.rs / hash.rs
│   ├── scanner/live/     # walkdir + statx
│   ├── scanner/tsk/      # optional libtsk FFI
│   └── output/           # table, json, csv, bodyfile
└── tests/tsk_integration.rs
```

## Responsible use

This tool is intended for **authorized** digital forensics, incident response, and research on systems and images you are allowed to examine. Do not use it to access data without permission.

## License

This project is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Sentinel Security.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities. Do not open public issues for undisclosed security problems.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
