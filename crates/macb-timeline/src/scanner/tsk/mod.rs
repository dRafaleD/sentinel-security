#![cfg(all(feature = "tsk", libtsk_available))]

mod ffi;
mod hash;
mod image;
mod ntfs;
mod partition;

use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use self::ffi::{
    TskFsFile, TskFsInfo, TskImgInfo, TSK_FS_DIR_WALK_FLAG_UNALLOC,
    TSK_FS_META_FLAG_ORPHAN, TSK_FS_META_FLAG_UNALLOC, TSK_FS_META_TYPE_DIR,
    TSK_FS_META_TYPE_REG,
};
use self::hash::hash_tsk_records;
use self::image::{collect_image_paths, detect_image_type};
use self::ntfs::{detect_ntfs_attr_mismatch, map_ntfs_times};
use self::partition::{
    detect_filesystem_offset, list_partitions, print_partition_table, resolve_partition_offset,
};
use super::FileSource;
use crate::model::MacbRecord;
use crate::scanner::options::{path_matches_filters, path_within_depth, ScanOptions};
use crate::scanner::tsk_types::TskMetaTimes;

pub use partition::PartitionInfo;

#[derive(Debug)]
pub struct TskScanner {
    image_path: PathBuf,
    partition: Option<u32>,
    offset: Option<u64>,
    options: ScanOptions,
}

impl TskScanner {
    pub fn new(
        image_path: PathBuf,
        partition: Option<u32>,
        offset: Option<u64>,
        options: ScanOptions,
    ) -> Result<Self> {
        if !image_path.exists() {
            bail!("disk image does not exist: {}", image_path.display());
        }

        if partition.is_some() && offset.is_some() {
            bail!("use either --partition or --offset, not both");
        }

        Ok(Self {
            image_path,
            partition,
            offset,
            options,
        })
    }

    pub fn list_partitions(&self) -> Result<Vec<PartitionInfo>> {
        let img = open_image(&self.image_path)?;
        let result = list_partitions(img);
        unsafe { ffi::tsk_img_close(img) };
        result
    }

    fn resolve_offset(&self, img: *mut TskImgInfo) -> Result<u64> {
        if let Some(offset) = self.offset {
            return Ok(offset);
        }

        if let Some(partition) = self.partition {
            return resolve_partition_offset(img, partition);
        }

        detect_filesystem_offset(img)
    }
}

impl FileSource for TskScanner {
    fn scan(&self, _path: &Path) -> Result<Vec<MacbRecord>> {
        let img = open_image(&self.image_path)?;

        let result = (|| {
            let offset = self.resolve_offset(img)?;
            let fs = open_filesystem(img, offset)?;
            let fs_type = unsafe { ffi::tsk_fs_info_get_ftype(fs) };
            let root_inum = unsafe { ffi::tsk_fs_get_root_inum(fs) };

            let mut context = WalkContext {
                records: Vec::new(),
                fs_type,
                options: self.options.clone(),
                scanned: 0,
            };

            let mut walk_flags = 0u32;
            if self.options.include_deleted {
                walk_flags |= TSK_FS_DIR_WALK_FLAG_UNALLOC;
            }

            let walk_result = unsafe {
                ffi::tsk_fs_dir_walk(
                    fs,
                    root_inum,
                    walk_flags,
                    dir_walk_callback,
                    &mut context as *mut WalkContext as *mut c_void,
                )
            };

            if walk_result != 0 {
                unsafe { ffi::tsk_fs_close(fs) };
                bail!("libtsk directory walk failed: {}", ffi::last_tsk_error());
            }

            if let Some(algorithm) = self.options.hash {
                hash_tsk_records(fs, &mut context.records, algorithm)?;
            }

            unsafe { ffi::tsk_fs_close(fs) };

            if !self.options.quiet {
                eprintln!("scanned {} paths", context.records.len());
            }

            Ok(context.records)
        })();

        unsafe { ffi::tsk_img_close(img) };
        result
    }
}

pub fn print_image_partitions(image_path: &Path) -> Result<String> {
    let img = open_image(image_path)?;
    let partitions = list_partitions(img)?;
    unsafe { ffi::tsk_img_close(img) };
    Ok(print_partition_table(image_path, &partitions))
}

pub(crate) fn open_filesystem(img: *mut TskImgInfo, offset: u64) -> Result<*mut TskFsInfo> {
    ffi::reset_tsk_error();
    let fs = unsafe { ffi::tsk_fs_open_img(img, offset, ffi::TSK_FS_TYPE_DETECT) };
    if fs.is_null() {
        bail!(
            "failed to open filesystem at offset {offset}: {}",
            ffi::last_tsk_error()
        );
    }
    Ok(fs)
}

fn open_image(image_path: &Path) -> Result<*mut TskImgInfo> {
    let segments = collect_image_paths(image_path);
    let image_type = detect_image_type(image_path);
    let c_strings: Result<Vec<CString>> = segments
        .iter()
        .map(|path| {
            CString::new(path.to_string_lossy().as_bytes())
                .with_context(|| format!("invalid image path {}", path.display()))
        })
        .collect();
    let c_strings = c_strings?;
    let pointers: Vec<*const i8> = c_strings.iter().map(|value| value.as_ptr()).collect();

    ffi::reset_tsk_error();
    let img = unsafe {
        ffi::tsk_img_open(
            pointers.len() as i32,
            pointers.as_ptr(),
            image_type,
            0,
        )
    };

    if img.is_null() {
        bail!(
            "failed to open disk image {}: {}",
            image_path.display(),
            ffi::last_tsk_error()
        );
    }

    Ok(img)
}

struct WalkContext {
    records: Vec<MacbRecord>,
    fs_type: u32,
    options: ScanOptions,
    scanned: usize,
}

extern "C" fn dir_walk_callback(
    file: *const TskFsFile,
    path: *const i8,
    ptr: *mut c_void,
) -> u8 {
    if file.is_null() || path.is_null() || ptr.is_null() {
        return 0;
    }

    let context = unsafe { &mut *(ptr as *mut WalkContext) };
    let meta = unsafe { ffi::tsk_fs_file_get_meta(file) };
    if meta.is_null() {
        return 0;
    }

    let meta_type = unsafe { ffi::tsk_fs_meta_get_type(meta) };
    if meta_type != TSK_FS_META_TYPE_REG && meta_type != TSK_FS_META_TYPE_DIR {
        return 0;
    }
    let is_dir = meta_type == TSK_FS_META_TYPE_DIR;
    let flags = unsafe { ffi::tsk_fs_meta_get_flags(meta) };
    let deleted = flags & TSK_FS_META_FLAG_UNALLOC != 0 || flags & TSK_FS_META_FLAG_ORPHAN != 0;

    let path_str = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let path_buf = PathBuf::from(&path_str);

    if !path_within_depth(&path_buf, context.options.max_depth)
        || !path_matches_filters(
            &path_buf,
            &context.options.include,
            &context.options.exclude,
        )
    {
        return 0;
    }

    context.scanned += 1;
    if !context.options.quiet && context.scanned % 1000 == 0 {
        eprintln!("scanned {} paths...", context.scanned);
    }

    let meta_times = TskMetaTimes {
        crtime: unsafe { ffi::tsk_fs_meta_get_crtime(meta) },
        atime: unsafe { ffi::tsk_fs_meta_get_atime(meta) },
        mtime: unsafe { ffi::tsk_fs_meta_get_mtime(meta) },
        ctime: unsafe { ffi::tsk_fs_meta_get_ctime(meta) },
    };

    let (mtime, atime, ctime, btime) = map_ntfs_times(context.fs_type, meta, &meta_times);
    let mut anomalies = Vec::new();
    if let Some(anomaly) = detect_ntfs_attr_mismatch(context.fs_type, meta) {
        anomalies.push(anomaly);
    }

    context.records.push(MacbRecord {
        path: path_buf,
        inode: Some(unsafe { ffi::tsk_fs_meta_get_addr(meta) }),
        mtime,
        atime,
        ctime,
        btime,
        size: unsafe { ffi::tsk_fs_meta_get_size(meta) },
        mode: Some(u32::from(unsafe { ffi::tsk_fs_meta_get_mode(meta) })),
        uid: Some(unsafe { ffi::tsk_fs_meta_get_uid(meta) }),
        gid: Some(unsafe { ffi::tsk_fs_meta_get_gid(meta) }),
        md5: None,
        sha256: None,
        deleted,
        is_dir,
        anomalies,
    });

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_partition_and_offset_together() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        std::fs::write(&image, b"x").unwrap();

        let err = TskScanner::new(image, Some(1), Some(0), ScanOptions::default()).unwrap_err();
        assert!(err.to_string().contains("partition"));
    }
}
