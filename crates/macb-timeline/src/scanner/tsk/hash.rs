#![cfg(all(feature = "tsk", libtsk_available))]

use std::path::Path;

use anyhow::{Result, bail};
use md5::{Digest, Md5};
use sha2::Sha256;

use super::ffi::{self, TskFsInfo};
use crate::hash::HashAlgorithm;
use crate::model::MacbRecord;

pub fn hash_tsk_records(
    fs: *mut TskFsInfo,
    records: &mut [MacbRecord],
    algorithm: HashAlgorithm,
) -> Result<()> {
    for record in records.iter_mut() {
        if record.is_dir || record.size == 0 {
            continue;
        }
        let Some(inode) = record.inode else {
            continue;
        };

        match hash_tsk_file(fs, inode, &record.path, record.size, algorithm) {
            Ok(digest) => match algorithm {
                HashAlgorithm::Md5 => record.md5 = Some(digest),
                HashAlgorithm::Sha256 => record.sha256 = Some(digest),
            },
            Err(err) => {
                eprintln!(
                    "warning: failed to hash {} from image: {err:#}",
                    record.path.display()
                );
            }
        }
    }

    Ok(())
}

fn hash_tsk_file(
    fs: *mut TskFsInfo,
    inode: u64,
    path: &Path,
    size: u64,
    algorithm: HashAlgorithm,
) -> Result<String> {
    let file = unsafe {
        ffi::tsk_fs_file_open_meta(fs, std::ptr::null_mut(), inode)
    };
    if file.is_null() {
        bail!(
            "failed to open {} for hashing: {}",
            path.display(),
            ffi::last_tsk_error()
        );
    }

    let result = read_and_hash(file, size, algorithm);
    unsafe { ffi::tsk_fs_file_close(file) };
    result
}

fn read_and_hash(
    file: *mut super::ffi::TskFsFile,
    size: u64,
    algorithm: HashAlgorithm,
) -> Result<String> {
    let mut offset = 0i64;
    let mut remaining = size;
    let mut buffer = vec![0u8; 64 * 1024];

    let digest = match algorithm {
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            while remaining > 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                let read = unsafe {
                    ffi::tsk_fs_file_read(
                        file,
                        offset,
                        buffer.as_mut_ptr() as *mut i8,
                        chunk,
                        ffi::TSK_FS_FILE_READ_FLAG_NONE,
                    )
                };
                if read < 0 {
                    bail!("libtsk read failed: {}", ffi::last_tsk_error());
                }
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read as usize]);
                offset += read as i64;
                remaining -= read as u64;
            }
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            while remaining > 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                let read = unsafe {
                    ffi::tsk_fs_file_read(
                        file,
                        offset,
                        buffer.as_mut_ptr() as *mut i8,
                        chunk,
                        ffi::TSK_FS_FILE_READ_FLAG_NONE,
                    )
                };
                if read < 0 {
                    bail!("libtsk read failed: {}", ffi::last_tsk_error());
                }
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read as usize]);
                offset += read as i64;
                remaining -= read as u64;
            }
            format!("{:x}", hasher.finalize())
        }
    };

    Ok(digest)
}
