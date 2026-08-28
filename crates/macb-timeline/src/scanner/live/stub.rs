use std::path::Path;

use anyhow::{Result, bail};

use super::super::{FileSource, ScanError};
use crate::model::MacbRecord;
use crate::scanner::options::ScanOptions;

pub struct LiveScanner {
    _follow_symlinks: bool,
    _jobs: usize,
    _options: ScanOptions,
}

impl LiveScanner {
    pub fn new(follow_symlinks: bool, jobs: usize, options: ScanOptions) -> Self {
        Self {
            _follow_symlinks: follow_symlinks,
            _jobs: jobs,
            _options: options,
        }
    }
}

impl FileSource for LiveScanner {
    fn scan(&self, _path: &Path) -> Result<Vec<MacbRecord>> {
        let _ = _path;
        bail!(ScanError::UnsupportedPlatform)
    }
}
