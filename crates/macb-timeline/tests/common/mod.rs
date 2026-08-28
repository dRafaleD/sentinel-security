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
    if command_available("dd")
        && command_available("mkfs.vfat")
        && command_available("mount")
        && command_available("umount")
    {
        return true;
    }
    eprintln!("skipping TSK test: dd/mkfs.vfat/mount/umount unavailable");
    false
}

pub fn require_partition_tools() -> bool {
    if command_available("dd")
        && command_available("parted")
        && command_available("mkfs.vfat")
        && command_available("mount")
        && command_available("umount")
    {
        return true;
    }
    eprintln!("skipping TSK test: dd/parted/mkfs.vfat/mount/umount unavailable");
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
    run_success(
        Command::new("mkfs.vfat").args([
            "-F",
            "32",
            "-n",
            "TESTVOL",
            path.to_str().expect("utf-8 path"),
        ]),
        "mkfs.vfat",
    )?;
    seed_fat_image(path, None)
}

/// MBR disk image with one FAT32 partition. Returns the partition byte offset.
pub fn create_mbr_fat_partitioned_image(path: &Path) -> io::Result<u64> {
    const PARTITION_START_SECTOR: u64 = 2048;
    const SECTOR_SIZE: u64 = 512;
    let byte_offset = PARTITION_START_SECTOR * SECTOR_SIZE;

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
            "16MiB",
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

    seed_fat_image(path, Some(byte_offset))?;

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

fn seed_fat_image(path: &Path, byte_offset: Option<u64>) -> io::Result<()> {
    let mount = std::env::temp_dir().join(format!("macb-fat-{}", std::process::id()));
    let mount_str = mount.to_string_lossy();
    let image_str = path.to_string_lossy();

    run_success(
        Command::new("sudo").args(["mkdir", "-p", &mount_str]),
        "mkdir mountpoint",
    )?;

    let loop_opts = match byte_offset {
        Some(offset) => format!("loop,offset={offset},rw"),
        None => "loop,rw".to_string(),
    };

    let mount_result = run_success(
        Command::new("sudo").args([
            "mount",
            "-o",
            &loop_opts,
            &image_str,
            &mount_str,
        ]),
        "mount",
    );

    if mount_result.is_err() {
        let _ = Command::new("sudo").args(["rmdir", &mount_str]).status();
        return mount_result;
    }

    let write_result = std::fs::write(mount.join("sample.txt"), b"sample");
    let _ = Command::new("sudo").args(["umount", &mount_str]).status();
    let _ = Command::new("sudo").args(["rmdir", &mount_str]).status();
    write_result.map_err(io::Error::other)?;

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
