use std::io::{self, Write};

use tabled::{Table, Tabled};

use crate::model::{MacbRecord, Severity, TimelineEvent};
use crate::output::{format_anomalies, format_timestamp};

#[derive(Tabled)]
struct RecordRow {
    path: String,
    inode: String,
    mtime: String,
    atime: String,
    ctime: String,
    btime: String,
    size: String,
    anomalies: String,
}

#[derive(Tabled)]
struct TimelineRow {
    timestamp: String,
    event_type: String,
    path: String,
    anomalies: String,
}

pub fn write_records_table(
    writer: &mut dyn Write,
    records: &[MacbRecord],
    min_severity: Severity,
) -> io::Result<()> {
    let rows: Vec<RecordRow> = records
        .iter()
        .map(|record| RecordRow {
            path: record.path.display().to_string(),
            inode: record
                .inode
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            mtime: format_timestamp(record.mtime),
            atime: format_timestamp(record.atime),
            ctime: format_timestamp(record.ctime),
            btime: format_timestamp(record.btime),
            size: record.size.to_string(),
            anomalies: format_anomalies(&record.anomalies, min_severity),
        })
        .collect();

    let table = Table::new(rows);
    writeln!(writer, "{table}")
}

pub fn write_timeline_table(
    writer: &mut dyn Write,
    events: &[TimelineEvent],
    min_severity: Severity,
) -> io::Result<()> {
    let rows: Vec<TimelineRow> = events
        .iter()
        .map(|event| TimelineRow {
            timestamp: format_timestamp(Some(event.timestamp)),
            event_type: event.event_type.label().to_string(),
            path: event.path.display().to_string(),
            anomalies: format_anomalies(&event.anomalies, min_severity),
        })
        .collect();

    let table = Table::new(rows);
    writeln!(writer, "{table}")
}
