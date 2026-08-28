pub mod anomalies;
pub mod cli;
pub mod hash;
pub mod model;
pub mod output;
pub mod scanner;
pub mod time_filter;
pub mod timeline;

pub use anomalies::annotate_records;
pub use hash::{hash_records, HashAlgorithm};
pub use cli::{Cli, Command, ScanArgs, TimelineArgs};
pub use model::{MacbRecord, OutputFormat, Severity, SortField, TimelineEvent};
pub use output::{write_records, write_timeline};
pub use scanner::{create_scanner, scan_path, FileSource, LiveScanner, ScanOptions};
pub use time_filter::{filter_records_by_time, filter_timeline_by_time, TimeRange};
pub use timeline::{
    build_timeline, filter_records, filter_timeline, sort_records, sort_timeline,
};

#[cfg(all(feature = "tsk", libtsk_available))]
pub use scanner::TskScanner;

#[cfg(all(feature = "tsk", libtsk_available))]
pub use scanner::tsk::print_image_partitions;
