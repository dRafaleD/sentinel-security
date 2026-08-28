#![cfg(all(feature = "tsk", libtsk_available))]

use std::path::{Path, PathBuf};

use crate::scanner::tsk_types;

pub fn collect_image_paths(image_path: &Path) -> Vec<PathBuf> {
    let extension = image_path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);

    if !matches!(extension.as_deref(), Some("e01")) {
        return vec![image_path.to_path_buf()];
    }

    let parent = image_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = image_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("image");

    let mut segments = Vec::new();
    segments.push(image_path.to_path_buf());

    for index in 2..=999 {
        let segment = parent.join(format!("{stem}.E{index:02}"));
        if segment.exists() {
            segments.push(segment);
        } else {
            break;
        }
    }

    segments
}

pub fn detect_image_type(image_path: &Path) -> u32 {
    tsk_types::detect_image_type(image_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn collects_ewf_segments_in_order() {
        let dir = tempdir().unwrap();
        let e01 = dir.path().join("evidence.E01");
        let e02 = dir.path().join("evidence.E02");
        fs::write(&e01, b"seg1").unwrap();
        fs::write(&e02, b"seg2").unwrap();

        let segments = collect_image_paths(&e01);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], e01);
        assert_eq!(segments[1], e02);
    }

    #[test]
    fn leaves_non_ewf_images_unsegmented() {
        let path = Path::new("/tmp/disk.dd");
        assert_eq!(collect_image_paths(path), vec![path.to_path_buf()]);
    }
}
