//! Shared helpers for TSK integration tests (Linux + libtsk only).

use std::io;
use std::path::Path;
use std::process::Command;

const PARTITION_START_SECTOR: u64 = 2048;
const SECTOR_SIZE: u64 = 512;

pub fn command_available(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {command}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn require_fat_tools() -> bool {
    if command_available("dd")
        && command_available("parted")
        && command_available("mkfs.vfat")
        && command_available("mcopy")
    {
        return true;
    }
    eprintln!("skipping TSK test: dd/parted/mkfs.vfat/mcopy unavailable");
    false
}

pub fn require_partition_tools() -> bool {
    require_fat_tools()
}

pub fn require_ntfs_tools() -> bool {
    if command_available("dd") && command_available("mkfs.ntfs") {
        return true;
    }
    eprintln!("skipping TSK test: dd/mkfs.ntfs unavailable");
    false
}

/// Small MBR disk with one FAT32 partition. Returns the partition byte offset.
pub fn create_fat_image(path: &Path) -> io::Result<u64> {
    create_partitioned_fat_image(path, 32, "16MiB")
}

/// MBR disk image with one FAT32 partition. Returns the partition byte offset.
pub fn create_mbr_fat_partitioned_image(path: &Path) -> io::Result<u64> {
    create_partitioned_fat_image(path, 32, "16MiB")
}

fn create_partitioned_fat_image(path: &Path, size_mb: u64, part_end: &str) -> io::Result<u64> {
    let byte_offset = PARTITION_START_SECTOR * SECTOR_SIZE;
    let image = path.to_string_lossy();

    run_success(
        Command::new("dd").args([
            "if=/dev/zero",
            &format!("of={image}"),
            "bs=1M",
            &format!("count={size_mb}"),
        ]),
        "dd",
    )?;

    run_success(
        Command::new("parted").args([
            "-s",
            path.to_str().expect("utf-8 path"),
            "mklabel",
            "msdos",
            "mkpart",
            "primary",
            "fat32",
            "2048s",
            part_end,
        ]),
        "parted",
    )?;

    run_success(
        Command::new("mkfs.vfat").args([
            "-F",
            "32",
            "-n",
            "TESTPART",
            "--offset",
            &PARTITION_START_SECTOR.to_string(),
            path.to_str().expect("utf-8 path"),
        ]),
        "mkfs.vfat",
    )?;

    seed_fat_image(path, byte_offset)?;

    Ok(byte_offset)
}

pub fn create_ntfs_image(path: &Path) -> io::Result<()> {
    let image = path.to_string_lossy();
    run_success(
        Command::new("dd").args([
            "if=/dev/zero",
            &format!("of={image}"),
            "bs=1M",
            "count=64",
        ]),
        "dd",
    )?;
    run_success(
        Command::new("mkfs.ntfs").args([
            "-F",
            "-f",
            "-L",
            "EVIDENCE",
            path.to_str().expect("utf-8 path"),
        ]),
        "mkfs.ntfs",
    )?;
    Ok(())
}

fn seed_fat_image(path: &Path, byte_offset: u64) -> io::Result<()> {
    let sample = path.with_extension("seed.txt");
    std::fs::write(&sample, b"sample")?;

    let image_target = format!("{}@@{byte_offset}", path.display());
    let output = Command::new("mcopy")
        .args([
            "-i",
            &image_target,
            sample.to_str().expect("utf-8 seed path"),
            "::sample.txt",
        ])
        .output()?;

    let _ = std::fs::remove_file(&sample);

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "mcopy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn run_success(command: &mut Command, name: &str) -> io::Result<()> {
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}
