use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use thiserror::Error;

use crate::model::MacbRecord;

pub trait FileSource {
    fn scan(&self, path: &Path) -> Result<Vec<MacbRecord>>;
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("permission denied: {0}")]
    PermissionDenied(PathBuf),
    #[error(
        "live MACB scanning requires Linux; run on the target host or use --image for offline analysis"
    )]
    UnsupportedPlatform,
}

pub mod live;
pub mod options;

#[cfg(feature = "tsk")]
pub mod tsk_types;

#[cfg(all(feature = "tsk", libtsk_available))]
pub mod tsk;

pub use live::LiveScanner;
pub use options::ScanOptions;

#[cfg(all(feature = "tsk", libtsk_available))]
pub use tsk::TskScanner;

pub fn create_scanner(
    follow_symlinks: bool,
    jobs: usize,
    options: ScanOptions,
    #[cfg(libtsk_available)] image: Option<PathBuf>,
    #[cfg(libtsk_available)] partition: Option<u32>,
    #[cfg(libtsk_available)] offset: Option<u64>,
) -> Result<Box<dyn FileSource>> {
    #[cfg(all(feature = "tsk", libtsk_available))]
    if let Some(image_path) = image {
        return Ok(Box::new(TskScanner::new(
            image_path,
            partition,
            offset,
            options,
        )?));
    }

    Ok(Box::new(LiveScanner::new(follow_symlinks, jobs, options)))
}

pub fn scan_path(
    scanner: &dyn FileSource,
    path: &Path,
    require_exists: bool,
) -> Result<Vec<MacbRecord>> {
    if require_exists && !path.exists() {
        bail!(ScanError::NotFound(path.to_path_buf()));
    }

    scanner
        .scan(path)
        .with_context(|| format!("failed to scan {}", path.display()))
}
