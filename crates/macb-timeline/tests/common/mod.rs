//! Shared helpers for TSK integration tests (Linux + libtsk only).

use std::io;
use std::path::Path;
use std::process::Command;

pub fn command_available(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {command}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn require_fat_tools() -> bool {
    if command_available("dd") && command_available("mkfs.vfat") {
        return true;
    }
    eprintln!("skipping TSK test: dd/mkfs.vfat unavailable");
    false
}

pub fn require_partition_tools() -> bool {
    if command_available("dd") && command_available("sfdisk") && command_available("mkfs.vfat") {
        return true;
    }
    eprintln!("skipping TSK test: dd/sfdisk/mkfs.vfat unavailable");
    false
}

pub fn require_ntfs_tools() -> bool {
    if command_available("dd") && command_available("mkfs.ntfs") {
        return true;
    }
    eprintln!("skipping TSK test: dd/mkfs.ntfs unavailable");
    false
}

pub fn create_fat_image(path: &Path) -> io::Result<()> {
    let image = path.to_string_lossy();
    run_success(
        Command::new("dd").args([
            "if=/dev/zero",
            &format!("of={image}"),
            "bs=1M",
            "count=4",
        ]),
        "dd",
    )?;
    run_success(Command::new("mkfs.vfat").arg(path), "mkfs.vfat")?;
    Ok(())
}

/// MBR disk image with one FAT32 partition. Returns the partition byte offset.
pub fn create_mbr_fat_partitioned_image(path: &Path) -> io::Result<u64> {
    const PARTITION_START_SECTOR: u64 = 2048;
    const SECTOR_SIZE: u64 = 512;

    let image = path.to_string_lossy();
    run_success(
        Command::new("dd").args([
            "if=/dev/zero",
            &format!("of={image}"),
            "bs=1M",
            "count=32",
        ]),
        "dd",
    )?;

    let mut sfdisk = Command::new("sfdisk")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    use std::io::Write;
    let mut stdin = sfdisk.stdin.take().expect("sfdisk stdin");
    stdin.write_all(b"label: dos\n,start,16M,type=c\n")?;
    drop(stdin);

    let output = sfdisk.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "sfdisk failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    run_success(
        Command::new("mkfs.vfat").args([
            "-F",
            "32",
            "-n",
            "TESTPART",
            "--offset",
            &PARTITION_START_SECTOR.to_string(),
            &path.to_string_lossy(),
        ]),
        "mkfs.vfat",
    )?;

    Ok(PARTITION_START_SECTOR * SECTOR_SIZE)
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
