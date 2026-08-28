use std::path::Path;

use anyhow::{Context, Result};
use glob::Pattern;

use crate::hash::HashAlgorithm;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_depth: Option<u32>,
    pub include: Vec<Pattern>,
    pub exclude: Vec<Pattern>,
    pub quiet: bool,
    pub recursive: bool,
    pub include_deleted: bool,
    pub hash: Option<HashAlgorithm>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            include: Vec::new(),
            exclude: Vec::new(),
            quiet: false,
            recursive: true,
            include_deleted: false,
            hash: None,
        }
    }
}

impl ScanOptions {
    pub fn build(
        max_depth: Option<u32>,
        recursive: bool,
        include: &[String],
        exclude: &[String],
        quiet: bool,
        include_deleted: bool,
        hash: Option<HashAlgorithm>,
    ) -> Result<Self> {
        let max_depth = match max_depth {
            Some(depth) => Some(depth),
            None if !recursive => Some(1),
            None => None,
        };

        Ok(Self {
            max_depth,
            include: compile_patterns(include)?,
            exclude: compile_patterns(exclude)?,
            quiet,
            recursive,
            include_deleted,
            hash,
        })
    }

    pub fn from_patterns(
        max_depth: Option<u32>,
        include: &[String],
        exclude: &[String],
        quiet: bool,
    ) -> Result<Self> {
        Self::build(max_depth, true, include, exclude, quiet, false, None)
    }
}

pub fn compile_patterns(patterns: &[String]) -> Result<Vec<Pattern>> {
    patterns
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))
        })
        .collect()
}

pub fn path_matches_filters(path: &Path, includes: &[Pattern], excludes: &[Pattern]) -> bool {
    let path_str = normalize_path_for_glob(path);

    if excludes
        .iter()
        .any(|pattern| pattern.matches(&path_str))
    {
        return false;
    }

    if includes.is_empty() {
        return true;
    }

    includes
        .iter()
        .any(|pattern| pattern.matches(&path_str))
}

pub fn path_within_depth(path: &Path, max_depth: Option<u32>) -> bool {
    match max_depth {
        None => true,
        Some(depth) => path_depth(path) <= depth,
    }
}

pub fn path_depth(path: &Path) -> u32 {
    path.components()
        .count()
        .saturating_sub(1)
        .try_into()
        .unwrap_or(u32::MAX)
}

fn normalize_path_for_glob(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_filters_matching_paths() {
        let excludes = compile_patterns(&["*.log".into()]).unwrap();
        assert!(!path_matches_filters(
            Path::new("/var/log/syslog.log"),
            &[],
            &excludes
        ));
        assert!(path_matches_filters(
            Path::new("/var/log/syslog"),
            &[],
            &excludes
        ));
    }

    #[test]
    fn include_requires_match_when_set() {
        let includes = compile_patterns(&["**/*.txt".into()]).unwrap();
        assert!(path_matches_filters(
            Path::new("/tmp/readme.txt"),
            &includes,
            &[]
        ));
        assert!(!path_matches_filters(
            Path::new("/tmp/readme.md"),
            &includes,
            &[]
        ));
    }

    #[test]
    fn depth_counts_from_root() {
        assert_eq!(path_depth(Path::new("/")), 0);
        assert_eq!(path_depth(Path::new("/etc")), 1);
        assert_eq!(path_depth(Path::new("/etc/passwd")), 2);
        assert!(path_within_depth(Path::new("/etc"), Some(1)));
        assert!(!path_within_depth(Path::new("/etc/passwd"), Some(1)));
    }

    #[test]
    fn non_recursive_sets_max_depth_one() {
        let options = ScanOptions::build(None, false, &[], &[], true, false, None).unwrap();
        assert_eq!(options.max_depth, Some(1));
    }
}
