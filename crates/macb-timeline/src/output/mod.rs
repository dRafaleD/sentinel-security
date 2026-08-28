use std::io::{self, Write};

use crate::model::{MacbRecord, Severity, TimelineEvent};

pub mod bodyfile;
pub mod csv;
pub mod json;
pub mod table;

#[cfg(test)]
mod tests;

pub use bodyfile::write_records_bodyfile;
pub use csv::write_records_csv;
pub use csv::write_timeline_csv;
pub use json::write_records_json;
pub use json::write_timeline_json;
pub use table::write_records_table;
pub use table::write_timeline_table;

pub fn write_records(
    writer: &mut dyn Write,
    records: &[MacbRecord],
    format: crate::model::OutputFormat,
    min_severity: Severity,
) -> io::Result<()> {
    match format {
        crate::model::OutputFormat::Table => write_records_table(writer, records, min_severity),
        crate::model::OutputFormat::Json => write_records_json(writer, records, min_severity),
        crate::model::OutputFormat::Csv => write_records_csv(writer, records, min_severity),
        crate::model::OutputFormat::Bodyfile => write_records_bodyfile(writer, records),
    }
}

pub fn write_timeline(
    writer: &mut dyn Write,
    events: &[TimelineEvent],
    format: crate::model::OutputFormat,
    min_severity: Severity,
) -> io::Result<()> {
    match format {
        crate::model::OutputFormat::Table => write_timeline_table(writer, events, min_severity),
        crate::model::OutputFormat::Json => write_timeline_json(writer, events, min_severity),
        crate::model::OutputFormat::Csv => write_timeline_csv(writer, events, min_severity),
        crate::model::OutputFormat::Bodyfile => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bodyfile output is only supported for the scan command",
            ));
        }
    }
}

pub(crate) fn format_anomalies(
    anomalies: &[crate::model::Anomaly],
    min_severity: Severity,
) -> String {
    anomalies
        .iter()
        .filter(|anomaly| anomaly.severity >= min_severity)
        .map(|anomaly| format!("[{}] {}", anomaly.severity.label(), anomaly.description))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn format_timestamp(timestamp: Option<chrono::DateTime<chrono::Utc>>) -> String {
    timestamp
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".to_string())
}
