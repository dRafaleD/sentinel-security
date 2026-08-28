#![cfg(all(feature = "tsk", libtsk_available))]

use super::ffi::{self, TskFsMeta, TSK_FS_TYPE_NTFS};
use crate::model::{Anomaly, AnomalyRule, MacbType, Severity};
use crate::scanner::tsk_types::{self, TskMetaTimes};

const COMPARE_SLACK_SECS: i64 = 1;

fn si_times(meta: *const TskFsMeta) -> TskMetaTimes {
    unsafe {
        TskMetaTimes {
            crtime: ffi::tsk_fs_meta_get_crtime(meta),
            atime: ffi::tsk_fs_meta_get_atime(meta),
            mtime: ffi::tsk_fs_meta_get_mtime(meta),
            ctime: ffi::tsk_fs_meta_get_ctime(meta),
        }
    }
}

fn fn_times(meta: *const TskFsMeta) -> TskMetaTimes {
    unsafe {
        TskMetaTimes {
            crtime: ffi::tsk_fs_meta_get_ntfs_fn_crtime(meta),
            atime: ffi::tsk_fs_meta_get_ntfs_fn_atime(meta),
            mtime: ffi::tsk_fs_meta_get_ntfs_fn_mtime(meta),
            ctime: ffi::tsk_fs_meta_get_ntfs_fn_ctime(meta),
        }
    }
}

pub fn detect_ntfs_attr_mismatch(
    fs_type: u32,
    meta: *const TskFsMeta,
) -> Option<Anomaly> {
    if fs_type != TSK_FS_TYPE_NTFS || meta.is_null() {
        return None;
    }

    let si_times = si_times(meta);
    let fn_times = fn_times(meta);

    let mismatches = [
        ("mtime", si_times.mtime, fn_times.mtime, MacbType::Modified),
        ("crtime", si_times.crtime, fn_times.crtime, MacbType::Born),
        ("atime", si_times.atime, fn_times.atime, MacbType::Accessed),
        ("ctime", si_times.ctime, fn_times.ctime, MacbType::Changed),
    ]
    .into_iter()
    .filter(|(_, left, right, _)| timestamps_differ(*left, *right))
    .map(|(label, _, _, _)| label.to_string())
    .collect::<Vec<_>>();

    if mismatches.is_empty() {
        return None;
    }

    Some(Anomaly {
        rule: AnomalyRule::NtfsSiFnMismatch,
        severity: Severity::High,
        description: format!(
            "NTFS $STANDARD_INFORMATION and $FILE_NAME timestamps differ ({})",
            mismatches.join(", ")
        ),
        timestamps_involved: vec![
            MacbType::Modified,
            MacbType::Born,
            MacbType::Accessed,
            MacbType::Changed,
        ],
    })
}

pub fn map_ntfs_times(
    fs_type: u32,
    meta: *const TskFsMeta,
    meta_times: &TskMetaTimes,
) -> (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
) {
    if fs_type != TSK_FS_TYPE_NTFS || meta.is_null() {
        return tsk_types::map_tsk_timestamps(fs_type, meta_times);
    }

    tsk_types::map_tsk_timestamps(fs_type, &si_times(meta))
}

fn timestamps_differ(left: i64, right: i64) -> bool {
    if left <= 0 || right <= 0 {
        return false;
    }
    (left - right).abs() > COMPARE_SLACK_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_small_timestamp_differences() {
        assert!(!timestamps_differ(1_700_000_000, 1_700_000_000));
        assert!(!timestamps_differ(1_700_000_000, 1_700_000_001));
    }

    #[test]
    fn detects_large_timestamp_differences() {
        assert!(timestamps_differ(1_700_000_000, 1_700_010_000));
    }
}
