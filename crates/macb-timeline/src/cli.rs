use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::model::{OutputFormat, SortField};

#[derive(Debug, Parser)]
#[command(
    name = "macb-timeline",
    about = "Scan directories and build MACB timestamp timelines with anomaly detection",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a live filesystem path and report MACB timestamps.
    Scan(ScanArgs),
    /// Build a chronological timeline from MACB timestamps.
    Timeline(TimelineArgs),
}

#[derive(Debug, Clone, Parser)]
pub struct ScanArgs {
    /// Path to scan on a live filesystem.
    #[cfg_attr(not(libtsk_available), arg(required = true))]
    #[cfg_attr(libtsk_available, arg(required_unless_present = "image"))]
    pub path: Option<PathBuf>,

    /// Recurse into subdirectories (default: true).
    #[arg(long = "no-recursive", default_value_t = true, action = clap::ArgAction::SetFalse)]
    pub recursive: bool,

    /// Follow symbolic links (not recommended for forensic use).
    #[arg(long, default_value_t = false)]
    pub follow_symlinks: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Table)]
    pub output: CliOutputFormat,

    /// Sort records by field. `timestamp` uses the latest available MACB time.
    #[arg(long, value_enum, default_value_t = CliSortField::Mtime)]
    pub sort: CliSortField,

    /// Show only records with anomalies.
    #[arg(long)]
    pub anomalies_only: bool,

    /// Minimum anomaly severity to include.
    #[arg(long, value_enum, default_value_t = CliSeverity::Info)]
    pub min_severity: CliSeverity,

    /// Number of parallel stat workers (0 = auto-detect CPU count).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,

    /// Maximum directory depth (0 = root only).
    #[arg(long)]
    pub max_depth: Option<u32>,

    /// Include only paths matching glob pattern (repeatable).
    #[arg(long = "include")]
    pub include: Vec<String>,

    /// Exclude paths matching glob pattern (repeatable).
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,

    /// Suppress progress and warning messages on stderr.
    #[arg(long)]
    pub quiet: bool,

    /// Write output to file instead of stdout.
    #[arg(short = 'o', long = "output-file")]
    pub output_file: Option<PathBuf>,

    /// Include records with any MACB timestamp on or after this time (RFC 3339 or YYYY-MM-DD).
    #[arg(long)]
    pub since: Option<String>,

    /// Include records with any MACB timestamp on or before this time (RFC 3339 or YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Compute file hashes (md5 or sha256). Applies to regular files on live scans.
    #[arg(long, value_name = "ALGORITHM")]
    pub hash: Option<String>,

    /// Include deleted/unallocated directory entries (TSK image scans only).
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub include_deleted: bool,

    /// Disk image path for offline TSK analysis.
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub image: Option<PathBuf>,

    /// Partition number inside the disk image (1-based).
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub partition: Option<u32>,

    /// Byte offset to filesystem inside the image.
    #[cfg(libtsk_available)]
    #[arg(long, conflicts_with = "partition")]
    pub offset: Option<u64>,

    /// List partitions in the disk image and exit.
    #[cfg(libtsk_available)]
    #[arg(long, requires = "image")]
    pub list_partitions: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct TimelineArgs {
    /// Path to scan on a live filesystem.
    #[cfg_attr(not(libtsk_available), arg(required = true))]
    #[cfg_attr(libtsk_available, arg(required_unless_present = "image"))]
    pub path: Option<PathBuf>,

    /// Recurse into subdirectories (default: true).
    #[arg(long = "no-recursive", default_value_t = true, action = clap::ArgAction::SetFalse)]
    pub recursive: bool,

    /// Follow symbolic links (not recommended for forensic use).
    #[arg(long, default_value_t = false)]
    pub follow_symlinks: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Table)]
    pub format: CliOutputFormat,

    /// Sort timeline events. Default is chronological timestamp order.
    /// Use mtime/atime/ctime/btime to show only that MACB event type.
    #[arg(long, value_enum, default_value_t = CliSortField::Timestamp)]
    pub sort: CliSortField,

    /// Show only events from records with anomalies.
    #[arg(long)]
    pub anomalies_only: bool,

    /// Minimum anomaly severity to include.
    #[arg(long, value_enum, default_value_t = CliSeverity::Info)]
    pub min_severity: CliSeverity,

    /// Number of parallel stat workers (0 = auto-detect CPU count).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,

    /// Maximum directory depth (0 = root only).
    #[arg(long)]
    pub max_depth: Option<u32>,

    /// Include only paths matching glob pattern (repeatable).
    #[arg(long = "include")]
    pub include: Vec<String>,

    /// Exclude paths matching glob pattern (repeatable).
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,

    /// Suppress progress and warning messages on stderr.
    #[arg(long)]
    pub quiet: bool,

    /// Write output to file instead of stdout.
    #[arg(short = 'o', long = "output-file")]
    pub output_file: Option<PathBuf>,

    /// Include records with any MACB timestamp on or after this time (RFC 3339 or YYYY-MM-DD).
    #[arg(long)]
    pub since: Option<String>,

    /// Include records with any MACB timestamp on or before this time (RFC 3339 or YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Compute file hashes (md5 or sha256). Applies to regular files on live scans.
    #[arg(long, value_name = "ALGORITHM")]
    pub hash: Option<String>,

    /// Include deleted/unallocated directory entries (TSK image scans only).
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub include_deleted: bool,

    /// Disk image path for offline TSK analysis.
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub image: Option<PathBuf>,

    /// Partition number inside the disk image (1-based).
    #[cfg(libtsk_available)]
    #[arg(long)]
    pub partition: Option<u32>,

    /// Byte offset to filesystem inside the image.
    #[cfg(libtsk_available)]
    #[arg(long, conflicts_with = "partition")]
    pub offset: Option<u64>,

    /// List partitions in the disk image and exit.
    #[cfg(libtsk_available)]
    #[arg(long, requires = "image")]
    pub list_partitions: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliOutputFormat {
    Table,
    Json,
    Csv,
    Bodyfile,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Table => Self::Table,
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::Csv => Self::Csv,
            CliOutputFormat::Bodyfile => Self::Bodyfile,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliSortField {
    Timestamp,
    Mtime,
    Atime,
    Ctime,
    Btime,
    Path,
}

impl From<CliSortField> for SortField {
    fn from(value: CliSortField) -> Self {
        match value {
            CliSortField::Timestamp => Self::Timestamp,
            CliSortField::Mtime => Self::Mtime,
            CliSortField::Atime => Self::Atime,
            CliSortField::Ctime => Self::Ctime,
            CliSortField::Btime => Self::Btime,
            CliSortField::Path => Self::Path,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl From<CliSeverity> for crate::model::Severity {
    fn from(value: CliSeverity) -> Self {
        match value {
            CliSeverity::Info => Self::Info,
            CliSeverity::Low => Self::Low,
            CliSeverity::Medium => Self::Medium,
            CliSeverity::High => Self::High,
        }
    }
}
