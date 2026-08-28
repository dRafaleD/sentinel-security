use std::cmp::Ordering;

use crate::model::{MacbRecord, MacbType, Severity, SortField, TimelineEvent};

pub fn build_timeline(records: &[MacbRecord]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for record in records {
        for event_type in [
            MacbType::Modified,
            MacbType::Accessed,
            MacbType::Changed,
            MacbType::Born,
        ] {
            if let Some(timestamp) = record.timestamp(event_type) {
                events.push(TimelineEvent {
                    timestamp,
                    event_type,
                    path: record.path.clone(),
                    anomalies: record.anomalies.clone(),
                });
            }
        }
    }

    events
}

pub fn sort_timeline(events: &mut Vec<TimelineEvent>, sort: SortField) {
    match sort {
        SortField::Path => events.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.timestamp.cmp(&right.timestamp))
                .then_with(|| left.event_type.label().cmp(right.event_type.label()))
        }),
        SortField::Mtime
        | SortField::Atime
        | SortField::Ctime
        | SortField::Btime => {
            let macb = sort_field_to_macb(sort);
            events.retain(|event| event.event_type == macb);
            events.sort_by(|left, right| {
                left.timestamp
                    .cmp(&right.timestamp)
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
        SortField::Timestamp => {
            events.sort_by(|left, right| {
                left.timestamp
                    .cmp(&right.timestamp)
                    .then_with(|| left.event_type.label().cmp(right.event_type.label()))
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
    }
}

pub fn sort_records(records: &mut [MacbRecord], sort: SortField) {
    match sort {
        SortField::Path => records.sort_by(|left, right| left.path.cmp(&right.path)),
        SortField::Timestamp => records.sort_by(|left, right| {
            compare_option_timestamps(left.latest_timestamp(), right.latest_timestamp())
                .then_with(|| left.path.cmp(&right.path))
        }),
        SortField::Mtime
        | SortField::Atime
        | SortField::Ctime
        | SortField::Btime => {
            let macb = sort_field_to_macb(sort);
            records.sort_by(|left, right| {
                compare_option_timestamps(left.timestamp(macb), right.timestamp(macb))
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
    }
}

pub fn filter_records(
    records: Vec<MacbRecord>,
    anomalies_only: bool,
    min_severity: Severity,
) -> Vec<MacbRecord> {
    if !anomalies_only {
        return records;
    }

    records
        .into_iter()
        .filter(|record| record.has_anomaly_at_or_above(min_severity))
        .collect()
}

pub fn filter_timeline(
    events: Vec<TimelineEvent>,
    anomalies_only: bool,
    min_severity: Severity,
) -> Vec<TimelineEvent> {
    if !anomalies_only {
        return events;
    }

    events
        .into_iter()
        .filter(|event| {
            event
                .anomalies
                .iter()
                .any(|anomaly| anomaly.severity >= min_severity)
        })
        .collect()
}

fn sort_field_to_macb(sort: SortField) -> MacbType {
    match sort {
        SortField::Mtime => MacbType::Modified,
        SortField::Atime => MacbType::Accessed,
        SortField::Ctime => MacbType::Changed,
        SortField::Btime => MacbType::Born,
        SortField::Path | SortField::Timestamp => MacbType::Modified,
    }
}

fn compare_option_timestamps(
    left: Option<chrono::DateTime<chrono::Utc>>,
    right: Option<chrono::DateTime<chrono::Utc>>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::anomalies::detect_anomalies;
    use crate::model::{Anomaly, AnomalyRule, MacbRecord};

    fn record(path: &str, mtime: i64, btime: Option<i64>) -> MacbRecord {
        let mut record = MacbRecord {
            path: Path::new(path).to_path_buf(),
            inode: Some(1),
            mtime: Some(Utc.timestamp_opt(mtime, 0).unwrap()),
            atime: Some(Utc.timestamp_opt(mtime, 0).unwrap()),
            ctime: Some(Utc.timestamp_opt(mtime, 0).unwrap()),
            btime: btime.map(|value| Utc.timestamp_opt(value, 0).unwrap()),
            size: 1,
            mode: None,
            uid: None,
            gid: None,
            md5: None,
            sha256: None,
            deleted: false,
            is_dir: false,
            anomalies: Vec::new(),
        };
        record.anomalies = detect_anomalies(&record);
        record
    }

    #[test]
    fn flattens_macb_into_events() {
        let records = vec![record("/tmp/a", 100, Some(90))];
        let events = build_timeline(&records);
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn filters_anomalies_only() {
        let mut suspicious = record("/tmp/bad", 100, Some(200));
        suspicious.anomalies = vec![Anomaly {
            rule: AnomalyRule::BtimeAfterMtime,
            severity: Severity::High,
            description: "test".into(),
            timestamps_involved: vec![MacbType::Born, MacbType::Modified],
        }];
        let clean = record("/tmp/good", 100, Some(90));

        let filtered = filter_records(vec![suspicious, clean], true, Severity::High);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, Path::new("/tmp/bad"));
    }

    #[test]
    fn timeline_keeps_clean_events_unless_anomalies_only() {
        let records = vec![record("/tmp/good", 100, Some(90))];
        let events = build_timeline(&records);
        let filtered = filter_timeline(events.clone(), false, Severity::High);
        assert_eq!(filtered.len(), events.len());
    }

    #[test]
    fn timeline_sorts_chronologically() {
        let records = vec![record("/tmp/a", 200, Some(100))];
        let mut events = build_timeline(&records);
        sort_timeline(&mut events, SortField::Timestamp);
        assert!(events.windows(2).all(|window| window[0].timestamp <= window[1].timestamp));
    }

    #[test]
    fn timeline_sort_mtime_keeps_only_modified_events() {
        let records = vec![record("/tmp/a", 200, Some(100))];
        let mut events = build_timeline(&records);
        sort_timeline(&mut events, SortField::Mtime);
        assert!(events.iter().all(|event| event.event_type == MacbType::Modified));
        assert_eq!(events.len(), 1);
    }

    fn record_with_times(path: &str, mtime: i64, atime: i64) -> MacbRecord {
        MacbRecord {
            path: Path::new(path).to_path_buf(),
            inode: Some(1),
            mtime: Some(Utc.timestamp_opt(mtime, 0).unwrap()),
            atime: Some(Utc.timestamp_opt(atime, 0).unwrap()),
            ctime: None,
            btime: None,
            size: 1,
            mode: None,
            uid: None,
            gid: None,
            md5: None,
            sha256: None,
            deleted: false,
            is_dir: false,
            anomalies: Vec::new(),
        }
    }

    #[test]
    fn scan_sort_timestamp_uses_latest_macb() {
        let mut records = vec![
            record_with_times("/tmp/old-mtime-new-atime", 100, 500),
            record_with_times("/tmp/new-mtime-old-atime", 400, 200),
        ];
        sort_records(&mut records, SortField::Timestamp);

        assert_eq!(records[0].path, Path::new("/tmp/new-mtime-old-atime"));
        assert_eq!(records[1].path, Path::new("/tmp/old-mtime-new-atime"));
    }
}
