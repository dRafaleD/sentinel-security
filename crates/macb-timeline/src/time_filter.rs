use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

use crate::model::{MacbRecord, TimelineEvent};

#[derive(Debug, Clone, Copy, Default)]
pub struct TimeRange {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl TimeRange {
    pub fn parse(since: Option<&str>, until: Option<&str>) -> Result<Self> {
        let since = since
            .map(|value| parse_time_bound(value, false))
            .transpose()?;
        let until = until
            .map(|value| parse_time_bound(value, true))
            .transpose()?;

        if let (Some(since), Some(until)) = (since, until) {
            if since > until {
                bail!("--since must be before or equal to --until");
            }
        }

        Ok(Self { since, until })
    }

    pub fn is_active(self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    pub fn contains(self, timestamp: DateTime<Utc>) -> bool {
        if let Some(since) = self.since {
            if timestamp < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if timestamp > until {
                return false;
            }
        }
        true
    }

    pub fn record_matches(self, record: &MacbRecord) -> bool {
        if !self.is_active() {
            return true;
        }

        [record.mtime, record.atime, record.ctime, record.btime]
            .into_iter()
            .flatten()
            .any(|timestamp| self.contains(timestamp))
    }
}

pub fn filter_records_by_time(
    records: Vec<MacbRecord>,
    range: TimeRange,
) -> Vec<MacbRecord> {
    if !range.is_active() {
        return records;
    }

    records
        .into_iter()
        .filter(|record| range.record_matches(record))
        .collect()
}

pub fn filter_timeline_by_time(
    events: Vec<TimelineEvent>,
    range: TimeRange,
) -> Vec<TimelineEvent> {
    if !range.is_active() {
        return events;
    }

    events
        .into_iter()
        .filter(|event| range.contains(event.timestamp))
        .collect()
}

fn parse_time_bound(value: &str, is_until: bool) -> Result<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("time value cannot be empty");
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(parsed.with_timezone(&Utc));
    }

    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = if is_until {
            date.and_hms_opt(23, 59, 59)
        } else {
            date.and_hms_opt(0, 0, 0)
        }
        .context("invalid date components")?;
        return Ok(Utc.from_utc_datetime(&naive));
    }

    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&naive));
    }

    bail!(
        "invalid time '{trimmed}': use RFC 3339 (e.g. 2024-01-15T10:30:00Z) or YYYY-MM-DD"
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::TimeZone;

    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn record(mtime: i64, atime: i64) -> MacbRecord {
        MacbRecord {
            path: PathBuf::from("/tmp/file"),
            inode: Some(1),
            mtime: Some(ts(mtime)),
            atime: Some(ts(atime)),
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
    fn parses_rfc3339_bound() {
        let parsed = parse_time_bound("2024-01-15T10:30:00Z", false).unwrap();
        assert_eq!(parsed.to_rfc3339(), "2024-01-15T10:30:00+00:00");
    }

    #[test]
    fn parses_date_only_bounds() {
        let since = parse_time_bound("2024-01-15", false).unwrap();
        let until = parse_time_bound("2024-01-15", true).unwrap();
        assert!(since < until);
        let midpoint = since + chrono::Duration::hours(12);
        assert!(TimeRange {
            since: Some(since),
            until: Some(until),
        }
        .contains(midpoint));
    }

    #[test]
    fn filters_records_with_any_macb_in_range() {
        let range = TimeRange {
            since: Some(ts(200)),
            until: Some(ts(300)),
        };
        let in_range = record(100, 250);
        let out_of_range = record(100, 50);

        let filtered = filter_records_by_time(vec![in_range, out_of_range], range);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].atime, Some(ts(250)));
    }

    #[test]
    fn filters_timeline_events_by_event_time() {
        let range = TimeRange {
            since: Some(ts(200)),
            until: Some(ts(250)),
        };
        let events = vec![
            TimelineEvent {
                timestamp: ts(100),
                event_type: crate::model::MacbType::Modified,
                path: "/tmp/a".into(),
                anomalies: Vec::new(),
            },
            TimelineEvent {
                timestamp: ts(220),
                event_type: crate::model::MacbType::Accessed,
                path: "/tmp/a".into(),
                anomalies: Vec::new(),
            },
        ];

        let filtered = filter_timeline_by_time(events, range);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].timestamp, ts(220));
    }

    #[test]
    fn rejects_since_after_until() {
        let err = TimeRange::parse(Some("2024-02-01"), Some("2024-01-01")).unwrap_err();
        assert!(err.to_string().contains("since"));
    }
}
