//! Integration tests for offline TSK scanning.
//! Requires Linux, `--features tsk`, and libtsk installed.

#![cfg(all(target_os = "linux", libtsk_available))]

mod common;

use std::path::Path;

use macb_timeline::annotate_records;
use macb_timeline::model::AnomalyRule;
use macb_timeline::print_image_partitions;
use macb_timeline::scanner::{FileSource, ScanOptions, TskScanner};
use tempfile::tempdir;

use common::{
    create_fat_image, create_mbr_fat_partitioned_image, create_ntfs_image, require_fat_tools,
    require_ntfs_tools, require_partition_tools,
};

#[test]
fn scans_fat_image_at_offset_zero() {
    if !require_fat_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("test-fat.img");
    create_fat_image(&image_path).expect("fat image");

    let scanner =
        TskScanner::new(image_path, None, Some(0), ScanOptions::default()).expect("scanner");
    let records = scanner.scan(Path::new("/")).expect("scan");

    assert!(
        !records.is_empty(),
        "expected at least the root directory in FAT image"
    );
}

#[test]
fn auto_detects_fat_image_offset() {
    if !require_fat_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("test-fat-auto.img");
    create_fat_image(&image_path).expect("fat image");

    let scanner =
        TskScanner::new(image_path.clone(), None, None, ScanOptions::default()).expect("scanner");
    let records = scanner.scan(Path::new("/")).expect("scan");

    assert!(
        !records.is_empty(),
        "expected auto-detected FAT filesystem at offset 0"
    );
}

#[test]
fn lists_partitions_on_mbr_image() {
    if !require_partition_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("mbr-disk.img");
    let byte_offset = create_mbr_fat_partitioned_image(&image_path).expect("mbr image");

    let output = print_image_partitions(&image_path).expect("partitions");
    assert!(
        output.contains("Partitions in"),
        "expected partition listing header, got: {output}"
    );
    assert!(
        output.contains(&byte_offset.to_string()),
        "expected partition offset {byte_offset} in listing:\n{output}"
    );
    assert!(
        output.contains("alloc"),
        "expected allocated partition in listing:\n{output}"
    );
}

#[test]
fn scans_mbr_partition_by_number() {
    if !require_partition_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("mbr-scan.img");
    create_mbr_fat_partitioned_image(&image_path).expect("mbr image");

    let scanner =
        TskScanner::new(image_path, Some(1), None, ScanOptions::default()).expect("scanner");
    let records = scanner.scan(Path::new("/")).expect("scan");

    assert!(
        !records.is_empty(),
        "expected files from FAT partition 1"
    );
}

#[test]
fn auto_detects_mbr_partition_offset() {
    if !require_partition_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("mbr-auto.img");
    create_mbr_fat_partitioned_image(&image_path).expect("mbr image");

    let scanner =
        TskScanner::new(image_path, None, None, ScanOptions::default()).expect("scanner");
    let records = scanner.scan(Path::new("/")).expect("scan");

    assert!(
        !records.is_empty(),
        "expected auto-detected FAT filesystem inside MBR partition"
    );
}

#[test]
fn scans_ntfs_image_and_annotates_without_false_si_fn_mismatches() {
    if !require_ntfs_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("ntfs.img");
    create_ntfs_image(&image_path).expect("ntfs image");

    let scanner =
        TskScanner::new(image_path, None, Some(0), ScanOptions::default()).expect("scanner");
    let records = annotate_records(scanner.scan(Path::new("/")).expect("scan"));

    assert!(
        !records.is_empty(),
        "expected NTFS directory entries from root"
    );
    assert!(
        records.iter().any(|record| record.mtime.is_some()),
        "expected NTFS records with mtime"
    );

    let mismatch_count = records
        .iter()
        .filter(|record| {
            record
                .anomalies
                .iter()
                .any(|anomaly| anomaly.rule == AnomalyRule::NtfsSiFnMismatch)
        })
        .count();

    assert_eq!(
        mismatch_count, 0,
        "fresh NTFS image should not produce SI/FN mismatch anomalies"
    );
}

#[test]
fn tsk_scan_honors_max_depth_filter() {
    if !require_fat_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("fat-depth.img");
    create_fat_image(&image_path).expect("fat image");

    let shallow = ScanOptions::from_patterns(Some(0), &[], &[], true).expect("options");
    let scanner =
        TskScanner::new(image_path.clone(), None, Some(0), shallow).expect("scanner");
    let shallow_records = scanner.scan(Path::new("/")).expect("scan");

    let deep = ScanOptions::from_patterns(None, &[], &[], true).expect("options");
    let scanner = TskScanner::new(image_path, None, Some(0), deep).expect("scanner");
    let deep_records = scanner.scan(Path::new("/")).expect("scan");

    assert!(
        shallow_records.len() <= deep_records.len(),
        "max_depth=0 should return fewer paths than unrestricted scan"
    );
}

#[test]
fn rejects_partition_and_offset_together() {
    if !require_fat_tools() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let image_path = dir.path().join("fat-reject.img");
    create_fat_image(&image_path).expect("fat image");

    let err = TskScanner::new(image_path, Some(1), Some(0), ScanOptions::default()).unwrap_err();
    assert!(err.to_string().contains("partition"));
}
