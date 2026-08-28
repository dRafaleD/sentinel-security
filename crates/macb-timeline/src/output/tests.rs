#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use chrono::{TimeZone, Utc};

    use crate::model::{Anomaly, AnomalyRule, MacbRecord, MacbType, OutputFormat, Severity, TimelineEvent};
    use crate::output::{write_records, write_timeline};

    fn sample_record() -> MacbRecord {
        MacbRecord {
            path: "/tmp/example.txt".into(),
            inode: Some(42),
            mtime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            atime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            ctime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            btime: Some(Utc.with_ymd_and_hms(2024, 3, 14, 10, 0, 0).unwrap()),
            size: 128,
            mode: None,
            uid: None,
            gid: None,
            md5: None,
            sha256: None,
            deleted: false,
            is_dir: false,
            anomalies: vec![Anomaly {
                rule: AnomalyRule::BtimeAfterMtime,
                severity: Severity::High,
                description: "test anomaly".into(),
                timestamps_involved: vec![MacbType::Born, MacbType::Modified],
            }],
        }
    }

    #[test]
    fn writes_bodyfile_records() {
        let record = MacbRecord {
            path: "/tmp/example.txt".into(),
            inode: Some(42),
            mtime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            atime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            ctime: Some(Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap()),
            btime: Some(Utc.with_ymd_and_hms(2024, 3, 14, 10, 0, 0).unwrap()),
            size: 128,
            mode: Some(0o100644),
            uid: Some(0),
            gid: Some(0),
            md5: Some("abc123".into()),
            sha256: None,
            deleted: false,
            is_dir: false,
            anomalies: Vec::new(),
        };

        let mut buffer = Cursor::new(Vec::new());
        write_records(&mut buffer, &[record], OutputFormat::Bodyfile, Severity::Info).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();
        assert!(output.starts_with("abc123|/tmp/example.txt|42|-/rw-r--r--|"));
    }

    #[test]
    fn writes_json_records() {
        let mut buffer = Cursor::new(Vec::new());
        write_records(
            &mut buffer,
            &[sample_record()],
            OutputFormat::Json,
            Severity::Info,
        )
        .unwrap();

        let output = String::from_utf8(buffer.into_inner()).unwrap();
        assert!(output.contains("example.txt"));
        assert!(output.contains("test anomaly"));
    }

    #[test]
    fn writes_csv_timeline() {
        let event = TimelineEvent {
            timestamp: Utc.with_ymd_and_hms(2024, 3, 15, 14, 22, 1).unwrap(),
            event_type: MacbType::Modified,
            path: "/tmp/example.txt".into(),
            anomalies: Vec::new(),
        };

        let mut buffer = Cursor::new(Vec::new());
        write_timeline(
            &mut buffer,
            &[event],
            OutputFormat::Csv,
            Severity::Info,
        )
        .unwrap();

        let output = String::from_utf8(buffer.into_inner()).unwrap();
        assert!(output.starts_with("timestamp,event_type,path,anomalies"));
        assert!(output.contains("/tmp/example.txt"));
    }
}
