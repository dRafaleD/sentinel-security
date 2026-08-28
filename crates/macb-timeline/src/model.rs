use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MacbType {
    #[serde(rename = "M")]
    Modified,
    #[serde(rename = "A")]
    Accessed,
    #[serde(rename = "C")]
    Changed,
    #[serde(rename = "B")]
    Born,
}

impl MacbType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Modified => "M",
            Self::Accessed => "A",
            Self::Changed => "C",
            Self::Born => "B",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyRule {
    BtimeAfterMtime,
    BtimeAfterAtime,
    MtimeInFuture,
    BtimeInFuture,
    CtimeBeforeMtime,
    AllTimestampsEqual,
    ZeroTimestamps,
    NtfsSiFnMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub rule: AnomalyRule,
    pub severity: Severity,
    pub description: String,
    pub timestamps_involved: Vec<MacbType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacbRecord {
    pub path: PathBuf,
    pub inode: Option<u64>,
    pub mtime: Option<DateTime<Utc>>,
    pub atime: Option<DateTime<Utc>>,
    pub ctime: Option<DateTime<Utc>>,
    pub btime: Option<DateTime<Utc>>,
    pub size: u64,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub is_dir: bool,
    pub anomalies: Vec<Anomaly>,
}

impl MacbRecord {
    pub fn timestamp(&self, kind: MacbType) -> Option<DateTime<Utc>> {
        match kind {
            MacbType::Modified => self.mtime,
            MacbType::Accessed => self.atime,
            MacbType::Changed => self.ctime,
            MacbType::Born => self.btime,
        }
    }

    /// Latest available MACB timestamp across M/A/C/B.
    pub fn latest_timestamp(&self) -> Option<DateTime<Utc>> {
        [self.mtime, self.atime, self.ctime, self.btime]
            .into_iter()
            .flatten()
            .max()
    }

    pub fn has_anomaly_at_or_above(&self, min: Severity) -> bool {
        self.anomalies
            .iter()
            .any(|anomaly| anomaly.severity >= min)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: MacbType,
    pub path: PathBuf,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Timestamp,
    Mtime,
    Atime,
    Ctime,
    Btime,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
    Bodyfile,
}
