#![cfg(feature = "tsk")]

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};

const TSK_IMG_TYPE_DETECT: u32 = 0;
const TSK_IMG_TYPE_RAW: u32 = 0x0000_0001;
const TSK_IMG_TYPE_AFF_AFF: u32 = 0x0000_0004;
const TSK_IMG_TYPE_AFF_AFD: u32 = 0x0000_0005;
const TSK_IMG_TYPE_EWF: u32 = 0x0000_000e;

const TSK_FS_TYPE_NTFS: u32 = 0x0000_0001;
const TSK_FS_TYPE_FAT12: u32 = 0x0000_0008;
const TSK_FS_TYPE_FAT16: u32 = 0x0000_0009;
const TSK_FS_TYPE_FAT32: u32 = 0x0000_000a;
const TSK_FS_TYPE_EXT2: u32 = 0x0000_0004;

#[derive(Debug, Clone, Copy)]
pub struct TskMetaTimes {
    pub crtime: i64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

pub fn detect_image_type(path: &Path) -> u32 {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);

    match extension.as_deref() {
        Some("e01") | Some("ex01") | Some("e02") | Some("e03") => TSK_IMG_TYPE_EWF,
        Some("aff") => TSK_IMG_TYPE_AFF_AFF,
        Some("afd") => TSK_IMG_TYPE_AFF_AFD,
        Some("raw") | Some("dd") | Some("img") => TSK_IMG_TYPE_RAW,
        _ => TSK_IMG_TYPE_DETECT,
    }
}

pub fn map_tsk_timestamps(
    fs_type: u32,
    times: &TskMetaTimes,
) -> (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
) {
    let mtime = timestamp_from_unix(times.mtime);
    let atime = timestamp_from_unix(times.atime);

    match fs_type {
        TSK_FS_TYPE_NTFS => {
            let ctime = timestamp_from_unix(times.ctime);
            let btime = timestamp_from_unix(times.crtime);
            (mtime, atime, ctime, btime)
        }
        TSK_FS_TYPE_FAT12 | TSK_FS_TYPE_FAT16 | TSK_FS_TYPE_FAT32 => {
            let btime = timestamp_from_unix(times.crtime);
            (mtime, atime, None, btime)
        }
        TSK_FS_TYPE_EXT2 => {
            let ctime = timestamp_from_unix(times.ctime);
            let btime = timestamp_from_unix(times.crtime);
            (mtime, atime, ctime, btime)
        }
        _ => {
            let ctime = timestamp_from_unix(times.ctime);
            let btime = timestamp_from_unix(times.crtime);
            (mtime, atime, ctime, btime)
        }
    }
}

fn timestamp_from_unix(secs: i64) -> Option<DateTime<Utc>> {
    if secs <= 0 {
        return None;
    }
    chrono::Utc.timestamp_opt(secs, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ewf_extension() {
        assert_eq!(
            detect_image_type(Path::new("/evidence/disk.E01")),
            TSK_IMG_TYPE_EWF
        );
    }

    #[test]
    fn detects_aff_extension() {
        assert_eq!(
            detect_image_type(Path::new("/evidence/image.aff")),
            TSK_IMG_TYPE_AFF_AFF
        );
    }

    #[test]
    fn maps_fat_without_ctime() {
        let times = TskMetaTimes {
            crtime: 1_700_000_000,
            atime: 1_700_000_100,
            mtime: 1_700_000_200,
            ctime: 1_700_000_300,
        };

        let (_, _, ctime, btime) = map_tsk_timestamps(TSK_FS_TYPE_FAT32, &times);
        assert!(ctime.is_none());
        assert!(btime.is_some());
    }

    #[test]
    fn maps_ntfs_with_all_timestamps() {
        let times = TskMetaTimes {
            crtime: 1_700_000_000,
            atime: 1_700_000_100,
            mtime: 1_700_000_200,
            ctime: 1_700_000_300,
        };

        let (mtime, atime, ctime, btime) = map_tsk_timestamps(TSK_FS_TYPE_NTFS, &times);
        assert!(mtime.is_some());
        assert!(atime.is_some());
        assert!(ctime.is_some());
        assert!(btime.is_some());
    }
}
