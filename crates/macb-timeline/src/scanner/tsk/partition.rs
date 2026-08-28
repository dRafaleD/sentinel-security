#![cfg(all(feature = "tsk", libtsk_available))]

use std::ffi::CStr;
use std::os::raw::c_void;
use std::path::Path;

use anyhow::{Result, bail};

use super::ffi::{
    self, TskImgInfo, TskVsPartInfo, TSK_VS_PART_FLAG_ALL, TSK_VS_PART_FLAG_ALLOC,
    TSK_VS_TYPE_DETECT,
};
use super::open_filesystem;

#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub slot: u32,
    pub start_sector: u64,
    pub length_sectors: u64,
    pub byte_offset: u64,
    pub description: String,
    pub allocated: bool,
}

pub fn list_partitions(image: *mut TskImgInfo) -> Result<Vec<PartitionInfo>> {
    let vs = unsafe { ffi::tsk_vs_open(image, 0, TSK_VS_TYPE_DETECT) };
    if vs.is_null() {
        bail!(
            "no partition table found in image: {}",
            ffi::last_tsk_error()
        );
    }

    let mut collector = PartitionCollector {
        partitions: Vec::new(),
        block_size: unsafe { ffi::tsk_vs_get_block_size(vs) },
        allocated_slot: 0,
    };

    // Walk one address at a time. libtsk exposes no stable public partition
    // count accessor, and its internal struct layout varies by version.
    for address in 0..u32::MAX {
        let walk_result = unsafe {
            ffi::tsk_vs_part_walk(
                vs,
                address,
                address,
                TSK_VS_PART_FLAG_ALL,
                vs_part_collect_callback,
                &mut collector as *mut PartitionCollector as *mut c_void,
            )
        };
        if walk_result != 0 {
            break;
        }
    }

    unsafe { ffi::tsk_vs_close(vs) };

    if collector.partitions.is_empty() {
        bail!("partition table contains no entries");
    }

    Ok(collector.partitions)
}

pub fn resolve_partition_offset(image: *mut TskImgInfo, partition: u32) -> Result<u64> {
    if partition == 0 {
        bail!("partition numbers are 1-based");
    }

    let partitions: Vec<PartitionInfo> = list_partitions(image)?
        .into_iter()
        .filter(|part| part.allocated)
        .collect();

    let selected = partitions
        .iter()
        .find(|part| part.slot == partition)
        .ok_or_else(|| {
            let summary = format_partition_table(&partitions);
            anyhow::anyhow!(
                "allocated partition {partition} not found.\nAvailable partitions:\n{summary}"
            )
        })?;

    Ok(selected.byte_offset)
}

pub fn detect_filesystem_offset(image: *mut TskImgInfo) -> Result<u64> {
    ffi::reset_tsk_error();
    if let Ok(fs) = open_filesystem(image, 0) {
        unsafe { ffi::tsk_fs_close(fs) };
        return Ok(0);
    }

    let partitions: Vec<PartitionInfo> = list_partitions(image)
        .unwrap_or_default()
        .into_iter()
        .filter(|part| part.allocated)
        .collect();

    for part in &partitions {
        ffi::reset_tsk_error();
        if let Ok(fs) = open_filesystem(image, part.byte_offset) {
            unsafe { ffi::tsk_fs_close(fs) };
            return Ok(part.byte_offset);
        }
    }

    let summary = format_partition_table(&partitions);
    bail!(
        "no supported filesystem found in image.\nTried offset 0 and allocated partitions:\n{summary}\nLast libtsk error: {}",
        ffi::last_tsk_error()
    );
}

pub fn format_partition_table(partitions: &[PartitionInfo]) -> String {
    if partitions.is_empty() {
        return "  (none)".to_string();
    }

    partitions
        .iter()
        .map(|part| {
            format!(
                "  {:>2}. offset={} bytes (sector {}, len {}), {} - {}",
                part.slot,
                part.byte_offset,
                part.start_sector,
                part.length_sectors,
                if part.allocated { "alloc" } else { "meta" },
                part.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn print_partition_table(image_path: &Path, partitions: &[PartitionInfo]) -> String {
    let mut output = format!("Partitions in {}:\n", image_path.display());
    output.push_str(&format_partition_table(partitions));
    output
}

struct PartitionCollector {
    partitions: Vec<PartitionInfo>,
    block_size: u32,
    allocated_slot: u32,
}

extern "C" fn vs_part_collect_callback(
    _vs: *mut ffi::TskVsInfo,
    part: *const TskVsPartInfo,
    ptr: *mut c_void,
) -> u8 {
    if part.is_null() || ptr.is_null() {
        return 0;
    }

    let collector = unsafe { &mut *(ptr as *mut PartitionCollector) };
    let start = unsafe { ffi::tsk_vs_part_get_start(part) };
    let len = unsafe { ffi::tsk_vs_part_get_len(part) };
    let flags = unsafe { ffi::tsk_vs_part_get_flags(part) };
    let desc_ptr = unsafe { ffi::tsk_vs_part_get_desc(part) };
    let description = if desc_ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(desc_ptr) }
            .to_string_lossy()
            .trim()
            .to_string()
    };

    let allocated = flags & TSK_VS_PART_FLAG_ALLOC != 0;
    let slot = if allocated {
        collector.allocated_slot += 1;
        collector.allocated_slot
    } else {
        0
    };

    collector.partitions.push(PartitionInfo {
        slot,
        start_sector: start,
        length_sectors: len,
        byte_offset: start * collector.block_size as u64,
        description,
        allocated,
    });

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_empty_partition_table() {
        assert_eq!(format_partition_table(&[]), "  (none)");
    }
}
