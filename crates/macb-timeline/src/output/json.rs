use std::io::{self, Write};

use serde::Serialize;

use crate::model::{MacbRecord, Severity, TimelineEvent};

#[derive(Serialize)]
struct RecordOutput<'a> {
    path: &'a std::path::Path,
    inode: Option<u64>,
    mtime: Option<chrono::DateTime<chrono::Utc>>,
    atime: Option<chrono::DateTime<chrono::Utc>>,
    ctime: Option<chrono::DateTime<chrono::Utc>>,
    btime: Option<chrono::DateTime<chrono::Utc>>,
    size: u64,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    md5: Option<String>,
    sha256: Option<String>,
    deleted: bool,
    is_dir: bool,
    anomalies: Vec<&'a crate::model::Anomaly>,
}

#[derive(Serialize)]
struct TimelineOutput<'a> {
    timestamp: chrono::DateTime<chrono::Utc>,
    event_type: crate::model::MacbType,
    path: &'a std::path::Path,
    anomalies: Vec<&'a crate::model::Anomaly>,
}

pub fn write_records_json(
    writer: &mut dyn Write,
    records: &[MacbRecord],
    min_severity: Severity,
) -> io::Result<()> {
    let payload: Vec<RecordOutput<'_>> = records
        .iter()
        .map(|record| RecordOutput {
            path: &record.path,
            inode: record.inode,
            mtime: record.mtime,
            atime: record.atime,
            ctime: record.ctime,
            btime: record.btime,
            size: record.size,
            mode: record.mode,
            uid: record.uid,
            gid: record.gid,
            md5: record.md5.clone(),
            sha256: record.sha256.clone(),
            deleted: record.deleted,
            is_dir: record.is_dir,
            anomalies: record
                .anomalies
                .iter()
                .filter(|anomaly| anomaly.severity >= min_severity)
                .collect(),
        })
        .collect();

    serde_json::to_writer_pretty(&mut *writer, &payload)?;
    writeln!(writer)
}

pub fn write_timeline_json(
    writer: &mut dyn Write,
    events: &[TimelineEvent],
    min_severity: Severity,
) -> io::Result<()> {
    let payload: Vec<TimelineOutput<'_>> = events
        .iter()
        .map(|event| TimelineOutput {
            timestamp: event.timestamp,
            event_type: event.event_type,
            path: &event.path,
            anomalies: event
                .anomalies
                .iter()
                .filter(|anomaly| anomaly.severity >= min_severity)
                .collect(),
        })
        .collect();

    serde_json::to_writer_pretty(&mut *writer, &payload)?;
    writeln!(writer)
}
