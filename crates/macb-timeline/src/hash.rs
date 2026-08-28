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

pub fn hash_records(records: &mut [MacbRecord], algorithm: HashAlgorithm, jobs: usize) -> Result<()> {
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
                eprintln!(
                    "warning: failed to hash {}: {err}",
                    record.path.display()
                );
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

fn hash_file(path: &Path, algorithm: HashAlgorithm) -> io::Result<String> {
    let mut file = File::open(path)?;
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
