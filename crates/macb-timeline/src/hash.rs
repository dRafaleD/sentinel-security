use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use anyhow::{Context, Result};
use md5::{Digest, Md5};
use rayon::prelude::*;
use sha2::Sha256;

use crate::model::MacbRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha256,
}

impl HashAlgorithm {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "md5" => Ok(Self::Md5),
            "sha256" | "sha-256" => Ok(Self::Sha256),
            _ => anyhow::bail!("unsupported hash algorithm '{value}' (use md5 or sha256)"),
        }
    }
}

pub fn hash_records(
    records: &mut [MacbRecord],
    algorithm: HashAlgorithm,
    jobs: usize,
) -> Result<()> {
    let pool = if jobs <= 1 {
        None
    } else {
        Some(
            rayon::ThreadPoolBuilder::new()
                .num_threads(jobs)
                .build()
                .context("failed to build hash thread pool")?,
        )
    };

    let hash_one = |record: &mut MacbRecord| {
        if record.is_dir || record.deleted {
            return;
        }
        match algorithm {
            HashAlgorithm::Md5 if record.md5.is_some() => return,
            HashAlgorithm::Sha256 if record.sha256.is_some() => return,
            _ => {}
        }
        if !record.path.exists() {
            return;
        }

        match hash_file(&record.path, algorithm) {
            Ok(digest) => match algorithm {
                HashAlgorithm::Md5 => record.md5 = Some(digest),
                HashAlgorithm::Sha256 => record.sha256 = Some(digest),
            },
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {}
            Err(err) => {
                eprintln!("warning: failed to hash {}: {err}", record.path.display());
            }
        }
    };

    if let Some(pool) = pool {
        pool.install(|| {
            records.par_iter_mut().for_each(hash_one);
        });
    } else {
        for record in records.iter_mut() {
            hash_one(record);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> io::Result<File> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::path::Component;
    let base = if path.is_absolute() { "/" } else { "." };
    let mut directory = open(
        base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let components: Vec<_> = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .collect();
    for (index, part) in components.iter().enumerate() {
        let name = match part {
            Component::Normal(name) => *name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported path component",
                ))
            }
        };
        let last = index + 1 == components.len();
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if !last {
            flags |= OFlags::DIRECTORY;
        }
        let descriptor = openat(&directory, name, flags, Mode::empty())?;
        if last {
            let file = File::from(descriptor);
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only regular files may be hashed",
                ));
            }
            return Ok(file);
        }
        directory = descriptor;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "no regular file selected",
    ))
}

#[cfg(not(unix))]
fn open_regular_file(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(windows)]
    let _parents = {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::path::{Component, Prefix};
        let absolute = std::path::absolute(path)?;
        if matches!(absolute.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::DeviceNS(_) | Prefix::Verbatim(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device namespace is not a file tree",
            ));
        }
        let mut parents = Vec::new();
        for parent in absolute
            .ancestors()
            .skip(1)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            let handle = std::fs::OpenOptions::new()
                .access_mode(0x80000000)
                .share_mode(1)
                .custom_flags(0x02200000)
                .open(parent)?;
            let metadata = handle.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ancestor reparse points are not hashed",
                ));
            }
            parents.push(handle);
        }
        parents
    };
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reparse points are not hashed",
            ));
        }
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only regular files may be hashed",
        ));
    }
    Ok(file)
}

fn hash_file(path: &Path, algorithm: HashAlgorithm) -> io::Result<String> {
    let mut file = open_regular_file(path)?;
    let mut buffer = [0u8; 64 * 1024];

    match algorithm {
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_files_still_hash_with_both_algorithms() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary");
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(
            hash_file(&path, HashAlgorithm::Md5).unwrap(),
            "5d41402abc4b2a76b9719d911017c592"
        );
        assert_eq!(hash_file(&path, HashAlgorithm::Sha256).unwrap().len(), 64);
    }

    #[test]
    fn parent_relative_paths_keep_their_normal_hash_behavior() {
        let directory = tempfile::tempdir().unwrap();
        let sub = directory.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"hello").unwrap();
        assert_eq!(
            hash_file(&sub.join("..").join("file"), HashAlgorithm::Md5).unwrap(),
            hash_file(&file, HashAlgorithm::Md5).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_junction_cannot_redirect_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("file"), b"outside").unwrap();
        let link = directory.path().join("junction");
        assert!(std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap()
            .status
            .success());
        assert!(hash_file(&link.join("file"), HashAlgorithm::Md5).is_err());
        std::fs::remove_dir(&link).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn links_special_files_and_parent_aliases_are_rejected_before_reading() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary");
        std::fs::write(&path, b"hello").unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(hash_file(&link, HashAlgorithm::Sha256).is_err());
        std::fs::remove_file(&link).unwrap();
        symlink(directory.path(), &link).unwrap();
        assert!(hash_file(&link.join("ordinary"), HashAlgorithm::Md5).is_err());
        let fifo = directory.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(hash_file(&fifo, HashAlgorithm::Md5).is_err());
        assert!(hash_file(Path::new("/dev/zero"), HashAlgorithm::Sha256).is_err());
        assert!(hash_file(directory.path(), HashAlgorithm::Sha256).is_err());
    }
}
