use chrono::{DateTime, Utc};

use crate::model::{
    Anomaly, AnomalyRule, MacbRecord, MacbType, Severity,
};

/// Ignore sub-second filesystem jitter when comparing timestamps.
const COMPARE_SLACK_SECS: i64 = 1;

pub fn detect_anomalies(record: &MacbRecord) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();
    let now = Utc::now();

    if let (Some(btime), Some(mtime)) = (record.btime, record.mtime) {
        if is_later(btime, mtime) {
            anomalies.push(Anomaly {
                rule: AnomalyRule::BtimeAfterMtime,
                severity: Severity::High,
                description: format!(
                    "Birth time ({btime}) is after modification time ({mtime})"
                ),
                timestamps_involved: vec![MacbType::Born, MacbType::Modified],
            });
        }
    }

    if let (Some(btime), Some(atime)) = (record.btime, record.atime) {
        if is_later(btime, atime) {
            anomalies.push(Anomaly {
                rule: AnomalyRule::BtimeAfterAtime,
                severity: Severity::Medium,
                description: format!(
                    "Birth time ({btime}) is after access time ({atime})"
                ),
                timestamps_involved: vec![MacbType::Born, MacbType::Accessed],
            });
        }
    }

    if let Some(mtime) = record.mtime {
        if mtime > now {
            anomalies.push(Anomaly {
                rule: AnomalyRule::MtimeInFuture,
                severity: Severity::High,
                description: format!("Modification time ({mtime}) is in the future"),
                timestamps_involved: vec![MacbType::Modified],
            });
        }
    }

    if let Some(btime) = record.btime {
        if btime > now {
            anomalies.push(Anomaly {
                rule: AnomalyRule::BtimeInFuture,
                severity: Severity::High,
                description: format!("Birth time ({btime}) is in the future"),
                timestamps_involved: vec![MacbType::Born],
            });
        }
    }

    if let (Some(ctime), Some(mtime)) = (record.ctime, record.mtime) {
        if is_later(mtime, ctime) {
            anomalies.push(Anomaly {
                rule: AnomalyRule::CtimeBeforeMtime,
                severity: Severity::Medium,
                description: format!(
                    "Change time ({ctime}) is before modification time ({mtime})"
                ),
                timestamps_involved: vec![MacbType::Changed, MacbType::Modified],
            });
        }
    }

    if all_timestamps_equal(record) {
        anomalies.push(Anomaly {
            rule: AnomalyRule::AllTimestampsEqual,
            severity: Severity::Low,
            description: "All available MACB timestamps are identical".to_string(),
            timestamps_involved: vec![
                MacbType::Modified,
                MacbType::Accessed,
                MacbType::Changed,
                MacbType::Born,
            ],
        });
    }

    if has_zero_timestamp(record) {
        anomalies.push(Anomaly {
            rule: AnomalyRule::ZeroTimestamps,
            severity: Severity::Medium,
            description: "One or more timestamps are at Unix epoch zero".to_string(),
            timestamps_involved: zero_timestamp_types(record),
        });
    }

    anomalies
}

pub fn annotate_records(mut records: Vec<MacbRecord>) -> Vec<MacbRecord> {
    for record in &mut records {
        let scanner_anomalies = std::mem::take(&mut record.anomalies);
        let detected = detect_anomalies(record);
        record.anomalies = merge_anomalies(scanner_anomalies, detected);
    }
    records
}

/// Merge scanner-detected anomalies (e.g. NTFS SI/FN) with generic MACB rules.
/// Rules already present from the scanner are kept; generic detection fills gaps.
fn merge_anomalies(existing: Vec<Anomaly>, detected: Vec<Anomaly>) -> Vec<Anomaly> {
    let mut merged = existing;
    for anomaly in detected {
        if merged.iter().all(|existing| existing.rule != anomaly.rule) {
            merged.push(anomaly);
        }
    }
    merged
}

fn all_timestamps_equal(record: &MacbRecord) -> bool {
    let timestamps: Vec<DateTime<Utc>> = [
        record.mtime,
        record.atime,
        record.ctime,
        record.btime,
    ]
    .into_iter()
    .flatten()
    .collect();

    timestamps.len() >= 2 && timestamps.windows(2).all(|window| window[0] == window[1])
}

fn has_zero_timestamp(record: &MacbRecord) -> bool {
    [record.mtime, record.atime, record.ctime, record.btime]
        .into_iter()
        .flatten()
        .any(is_epoch_zero)
}

fn zero_timestamp_types(record: &MacbRecord) -> Vec<MacbType> {
    let mut types = Vec::new();
    if record.mtime.is_some_and(is_epoch_zero) {
        types.push(MacbType::Modified);
    }
    if record.atime.is_some_and(is_epoch_zero) {
        types.push(MacbType::Accessed);
    }
    if record.ctime.is_some_and(is_epoch_zero) {
        types.push(MacbType::Changed);
    }
    if record.btime.is_some_and(is_epoch_zero) {
        types.push(MacbType::Born);
    }
    types
}

fn is_epoch_zero(timestamp: DateTime<Utc>) -> bool {
    timestamp.timestamp() == 0
}

fn is_later(left: DateTime<Utc>, right: DateTime<Utc>) -> bool {
    left.timestamp() > right.timestamp() + COMPARE_SLACK_SECS
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::model::{MacbRecord, MacbType};

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn base_record() -> MacbRecord {
        MacbRecord {
            path: "/tmp/test".into(),
            inode: Some(1),
            mtime: Some(ts(1_700_000_000)),
            atime: Some(ts(1_700_000_100)),
            ctime: Some(ts(1_700_000_200)),
            btime: Some(ts(1_699_999_900)),
            size: 42,
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
    fn detects_btime_after_mtime() {
        let mut record = base_record();
        record.btime = Some(ts(1_700_000_500));
        record.mtime = Some(ts(1_700_000_000));

        let anomalies = detect_anomalies(&record);
        assert!(anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::BtimeAfterMtime));
    }

    #[test]
    fn detects_future_mtime() {
        let mut record = base_record();
        record.mtime = Some(Utc::now() + chrono::Duration::days(1));

        let anomalies = detect_anomalies(&record);
        assert!(anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::MtimeInFuture));
    }

    #[test]
    fn detects_equal_timestamps() {
        let mut record = base_record();
        let same = ts(1_700_000_000);
        record.mtime = Some(same);
        record.atime = Some(same);
        record.ctime = Some(same);
        record.btime = Some(same);

        let anomalies = detect_anomalies(&record);
        assert!(anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::AllTimestampsEqual));
    }

    #[test]
    fn detects_ctime_before_mtime() {
        let mut record = base_record();
        record.ctime = Some(ts(1_699_999_000));
        record.mtime = Some(ts(1_700_000_000));

        let anomalies = detect_anomalies(&record);
        assert!(anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::CtimeBeforeMtime));
    }

    #[test]
    fn detects_zero_timestamps() {
        let mut record = base_record();
        record.mtime = Some(ts(0));

        let anomalies = detect_anomalies(&record);
        assert!(anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::ZeroTimestamps));
    }

    #[test]
    fn ignores_one_second_ctime_jitter() {
        let mut record = base_record();
        record.mtime = Some(ts(1_700_000_001));
        record.ctime = Some(ts(1_700_000_000));

        let anomalies = detect_anomalies(&record);
        assert!(!anomalies
            .iter()
            .any(|a| a.rule == AnomalyRule::CtimeBeforeMtime));
    }

    #[test]
    fn missing_btime_is_not_an_anomaly() {
        let mut record = base_record();
        record.btime = None;

        let anomalies = detect_anomalies(&record);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn annotate_records_preserves_scanner_anomalies() {
        let mut record = base_record();
        record.btime = Some(ts(1_700_000_500));
        record.mtime = Some(ts(1_700_000_000));
        record.anomalies = vec![Anomaly {
            rule: AnomalyRule::NtfsSiFnMismatch,
            severity: Severity::High,
            description: "NTFS SI/FN mismatch from scanner".into(),
            timestamps_involved: vec![MacbType::Modified],
        }];

        let annotated = annotate_records(vec![record]);
        let rules: Vec<AnomalyRule> = annotated[0].anomalies.iter().map(|a| a.rule).collect();

        assert!(rules.contains(&AnomalyRule::NtfsSiFnMismatch));
        assert!(rules.contains(&AnomalyRule::BtimeAfterMtime));
    }

    #[test]
    fn annotate_records_dedupes_same_rule() {
        let mut record = base_record();
        record.anomalies = vec![Anomaly {
            rule: AnomalyRule::BtimeAfterMtime,
            severity: Severity::High,
            description: "scanner copy".into(),
            timestamps_involved: vec![MacbType::Born, MacbType::Modified],
        }];
        record.btime = Some(ts(1_700_000_500));
        record.mtime = Some(ts(1_700_000_000));

        let annotated = annotate_records(vec![record]);
        let count = annotated[0]
            .anomalies
            .iter()
            .filter(|a| a.rule == AnomalyRule::BtimeAfterMtime)
            .count();

        assert_eq!(count, 1);
        assert_eq!(
            annotated[0].anomalies[0].description,
            "scanner copy"
        );
    }
}
