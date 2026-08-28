use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use rayon::prelude::*;
use rustix::fs::{AtFlags, CWD, FileType, Statx, StatxFlags};
use walkdir::WalkDir;

use super::super::FileSource;
use crate::model::MacbRecord;
use crate::scanner::options::{path_matches_filters, path_within_depth, ScanOptions};

pub struct LiveScanner {
    follow_symlinks: bool,
    jobs: usize,
    options: ScanOptions,
}

impl LiveScanner {
    pub fn new(follow_symlinks: bool, jobs: usize, options: ScanOptions) -> Self {
        Self {
            follow_symlinks,
            jobs,
            options,
        }
    }

    fn stat_record(path: &Path) -> Result<MacbRecord, io::Error> {
        match statx_record(path) {
            Ok(record) => Ok(record),
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                let metadata = fs::symlink_metadata(path)?;
                Ok(record_from_metadata(path, &metadata, None))
            }
            Err(err) => Err(err),
        }
    }

    fn collect_paths(&self, root: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut walker = WalkDir::new(root).follow_links(self.follow_symlinks);

        if let Some(depth) = self.options.max_depth {
            walker = walker.max_depth(depth as usize);
        } else if !self.options.recursive {
            walker = walker.max_depth(1);
        }

        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    if !self.options.quiet {
                        eprintln!("warning: {err}");
                    }
                    continue;
                }
            };

            let path = entry.path().to_path_buf();
            if !path_within_depth(&path, self.options.max_depth)
                || !path_matches_filters(
                    &path,
                    &self.options.include,
                    &self.options.exclude,
                )
            {
                continue;
            }

            let file_type = entry.file_type();
            if file_type.is_dir() || file_type.is_file() || file_type.is_symlink() {
                paths.push(path);
            }
        }

        if !self.options.quiet {
            eprintln!("discovered {} paths", paths.len());
        }

        paths
    }

    fn stat_paths(&self, paths: Vec<PathBuf>) -> Vec<MacbRecord> {
        let jobs = resolve_jobs(self.jobs);
        let quiet = self.options.quiet;

        let map_record = |path: &PathBuf| match Self::stat_record(path) {
            Ok(record) => Some(record),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                if !quiet {
                    eprintln!("warning: permission denied for {}", path.display());
                }
                None
            }
            Err(err) => {
                if !quiet {
                    eprintln!("warning: failed to stat {}: {err}", path.display());
                }
                None
            }
        };

        let records: Vec<MacbRecord> = if jobs <= 1 {
            paths.iter().filter_map(map_record).collect()
        } else {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(jobs)
                .build()
                .expect("failed to build rayon thread pool");

            pool.install(|| paths.par_iter().filter_map(map_record).collect())
        };

        if !quiet {
            eprintln!("scanned {} paths", records.len());
        }

        records
    }
}

impl FileSource for LiveScanner {
    fn scan(&self, path: &Path) -> Result<Vec<MacbRecord>> {
        let paths = self.collect_paths(path);
        Ok(self.stat_paths(paths))
    }
}

fn resolve_jobs(requested: usize) -> usize {
    if requested > 0 {
        return requested;
    }

    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn statx_record(path: &Path) -> Result<MacbRecord, io::Error> {
    let flags = AtFlags::SYMLINK_NOFOLLOW;
    let mask = StatxFlags::BASIC_STATS | StatxFlags::BTIME;

    let statx: Statx = rustix::fs::statx(CWD, path, flags, mask).map_err(io_err)?;

    let btime = if (statx.stx_mask & StatxFlags::BTIME.bits()) != 0
        && !(statx.stx_btime.tv_sec == 0 && statx.stx_btime.tv_nsec == 0)
    {
        timestamp_from_statx(statx.stx_btime.tv_sec, statx.stx_btime.tv_nsec)
    } else {
        None
    };

    Ok(MacbRecord {
        path: path.to_path_buf(),
        inode: Some(statx.stx_ino),
        mtime: timestamp_from_statx(statx.stx_mtime.tv_sec, statx.stx_mtime.tv_nsec),
        atime: timestamp_from_statx(statx.stx_atime.tv_sec, statx.stx_atime.tv_nsec),
        ctime: timestamp_from_statx(statx.stx_ctime.tv_sec, statx.stx_ctime.tv_nsec),
        btime,
        size: statx.stx_size,
        mode: Some(statx.stx_mode as u32),
        uid: Some(statx.stx_uid),
        gid: Some(statx.stx_gid),
        md5: None,
        sha256: None,
        deleted: false,
        is_dir: FileType::from_raw_mode(statx.stx_mode.into()) == FileType::Directory,
        anomalies: Vec::new(),
    })
}

fn record_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    inode: Option<u64>,
) -> MacbRecord {
    MacbRecord {
        path: path.to_path_buf(),
        inode: inode.or(Some(metadata.ino())),
        mtime: timestamp_from_secs(metadata.mtime()),
        atime: timestamp_from_secs(metadata.atime()),
        ctime: timestamp_from_secs(metadata.ctime()),
        btime: None,
        size: metadata.len(),
        mode: Some(metadata.mode()),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        md5: None,
        sha256: None,
        deleted: false,
        is_dir: metadata.is_dir(),
        anomalies: Vec::new(),
    }
}

fn timestamp_from_statx(secs: i64, nsecs: u32) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, nsecs).single()
}

fn timestamp_from_secs(secs: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single()
}

fn io_err(err: rustix::io::Errno) -> io::Error {
    match err {
        rustix::io::Errno::NOSYS => io::Error::new(io::ErrorKind::Unsupported, "statx unavailable"),
        rustix::io::Errno::ACCESS => {
            io::Error::new(io::ErrorKind::PermissionDenied, "permission denied")
        }
        rustix::io::Errno::NOENT => io::Error::new(io::ErrorKind::NotFound, "not found"),
        _ => io::Error::from_raw_os_error(err.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;
    use crate::anomalies::detect_anomalies;

    #[test]
    fn scans_temporary_directory() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("sample.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "hello").unwrap();

        let scanner = LiveScanner::new(false, 1, ScanOptions::default());
        let records = scanner.scan(dir.path()).unwrap();
        let record = records
            .iter()
            .find(|record| record.path == file_path)
            .expect("sample file record");

        assert!(record.mtime.is_some());
        assert!(record.atime.is_some());
        assert!(record.ctime.is_some());
        let annotated = detect_anomalies(record);
        assert!(record.btime.is_some() || annotated.is_empty());
    }

    #[test]
    fn parallel_scan_matches_sequential() {
        let dir = tempdir().unwrap();
        for index in 0..8 {
            let file_path = dir.path().join(format!("file-{index}.txt"));
            fs::write(file_path, format!("content-{index}")).unwrap();
        }

        let sequential = LiveScanner::new(false, 1, ScanOptions::default())
            .scan(dir.path())
            .unwrap();
        let parallel = LiveScanner::new(false, 4, ScanOptions::default()).scan(dir.path()).unwrap();

        assert_eq!(sequential.len(), parallel.len());
    }
}
