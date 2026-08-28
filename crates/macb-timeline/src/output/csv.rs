use std::io::{self, Write};

use crate::model::{MacbRecord, Severity, TimelineEvent};
use crate::output::{format_anomalies, format_timestamp};

pub fn write_records_csv(
    writer: &mut dyn Write,
    records: &[MacbRecord],
    min_severity: Severity,
) -> io::Result<()> {
    writeln!(
        writer,
        "path,inode,mtime,atime,ctime,btime,size,anomalies"
    )?;

    for record in records {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},\"{}\"",
            csv_escape(&record.path.display().to_string()),
            record
                .inode
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            format_timestamp(record.mtime),
            format_timestamp(record.atime),
            format_timestamp(record.ctime),
            format_timestamp(record.btime),
            record.size,
            csv_escape(&format_anomalies(&record.anomalies, min_severity)),
        )?;
    }

    Ok(())
}

pub fn write_timeline_csv(
    writer: &mut dyn Write,
    events: &[TimelineEvent],
    min_severity: Severity,
) -> io::Result<()> {
    writeln!(writer, "timestamp,event_type,path,anomalies")?;

    for event in events {
        writeln!(
            writer,
            "{},{},{},\"{}\"",
            format_timestamp(Some(event.timestamp)),
            event.event_type.label(),
            csv_escape(&event.path.display().to_string()),
            csv_escape(&format_anomalies(&event.anomalies, min_severity)),
        )?;
    }

    Ok(())
}

fn csv_escape(value: &str) -> String {
    value.replace('"', "\"\"")
}
