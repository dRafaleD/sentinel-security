#![cfg(all(feature = "tsk", libtsk_available))]

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;

pub const TSK_VS_TYPE_DETECT: u32 = 0;
pub const TSK_VS_PART_FLAG_ALLOC: u8 = 0x01;
pub const TSK_FS_TYPE_DETECT: u32 = 0;
pub const TSK_FS_TYPE_NTFS: u32 = 0x0000_0001;
pub const TSK_FS_META_TYPE_REG: u32 = 1;
pub const TSK_FS_META_TYPE_DIR: u32 = 2;
pub const TSK_FS_DIR_WALK_FLAG_UNALLOC: u32 = 0x02;
pub const TSK_FS_META_FLAG_UNALLOC: u8 = 0x02;
pub const TSK_FS_META_FLAG_ORPHAN: u8 = 0x20;
pub const TSK_FS_FILE_READ_FLAG_NONE: u32 = 0;

#[repr(C)]
pub struct TskImgInfo {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TskVsInfo {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TskFsInfo {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TskFsMeta {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TskFsFile {
    _private: [u8; 0],
}

#[repr(C)]
pub struct TskVsPartInfo {
    _private: [u8; 0],
}

pub type VsPartWalkCallback =
    extern "C" fn(*mut TskVsInfo, *const TskVsPartInfo, *mut c_void) -> u8;
pub type DirWalkCallback =
    extern "C" fn(*const TskFsFile, *const c_char, *mut c_void) -> u8;

extern "C" {
    pub fn tsk_img_open(
        num_img: c_int,
        images: *const *const c_char,
        type_: u32,
        ssize: c_int,
    ) -> *mut TskImgInfo;
    pub fn tsk_img_close(img: *mut TskImgInfo);

    pub fn tsk_vs_open(img: *mut TskImgInfo, offset: u64, type_: u32) -> *mut TskVsInfo;
    pub fn tsk_vs_close(vs: *mut TskVsInfo);
    pub fn tsk_vs_part_walk(
        vs: *mut TskVsInfo,
        start: u64,
        last: u64,
        flags: u32,
        action: VsPartWalkCallback,
        ptr: *mut c_void,
    ) -> u8;

    pub fn tsk_fs_open_img(
        img: *mut TskImgInfo,
        offset: u64,
        ftype: u32,
    ) -> *mut TskFsInfo;
    pub fn tsk_fs_close(fs: *mut TskFsInfo);
    pub fn tsk_fs_dir_walk(
        fs: *mut TskFsInfo,
        inode: u64,
        flags: u32,
        action: DirWalkCallback,
        ptr: *mut c_void,
    ) -> u8;

    pub fn tsk_fs_file_open_meta(
        fs: *mut TskFsInfo,
        fs_file: *mut TskFsFile,
        addr: u64,
    ) -> *mut TskFsFile;
    pub fn tsk_fs_file_close(file: *mut TskFsFile);
    pub fn tsk_fs_file_read(
        file: *mut TskFsFile,
        offset: i64,
        buf: *mut c_char,
        len: usize,
        flags: u32,
    ) -> isize;

    pub fn tsk_error_get_errstr() -> *const c_char;
    pub fn tsk_error_reset();
}

#[inline]
unsafe fn read_field<T: Copy>(ptr: *const u8, offset: usize) -> T {
    *((ptr.add(offset)) as *const T)
}

#[inline]
pub unsafe fn tsk_vs_get_block_size(vs: *const TskVsInfo) -> u32 {
    if vs.is_null() {
        0
    } else {
        read_field(vs as *const u8, 32)
    }
}

#[inline]
pub unsafe fn tsk_fs_get_root_inum(fs: *const TskFsInfo) -> u64 {
    if fs.is_null() {
        0
    } else {
        read_field(fs as *const u8, 32)
    }
}

#[inline]
pub unsafe fn tsk_fs_info_get_ftype(fs: *const TskFsInfo) -> u32 {
    if fs.is_null() {
        0
    } else {
        read_field(fs as *const u8, 112)
    }
}

#[inline]
pub unsafe fn tsk_fs_file_get_meta(file: *const TskFsFile) -> *const TskFsMeta {
    if file.is_null() {
        std::ptr::null()
    } else {
        read_field(file as *const u8, 16)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_type(meta: *const TskFsMeta) -> u32 {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 16)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_flags(meta: *const TskFsMeta) -> u8 {
    if meta.is_null() {
        0
    } else {
        read_field::<u32>(meta as *const u8, 4) as u8
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_addr(meta: *const TskFsMeta) -> u64 {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 8)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_size(meta: *const TskFsMeta) -> u64 {
    if meta.is_null() {
        0
    } else {
        read_field::<i64>(meta as *const u8, 32).max(0) as u64
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_mode(meta: *const TskFsMeta) -> u16 {
    if meta.is_null() {
        0
    } else {
        read_field::<i32>(meta as *const u8, 20) as u16
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_uid(meta: *const TskFsMeta) -> u32 {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 40)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_gid(meta: *const TskFsMeta) -> u32 {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 44)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_mtime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 48)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_atime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 64)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_ctime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 80)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_crtime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 96)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_ntfs_fn_crtime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 112)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_ntfs_fn_mtime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 128)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_ntfs_fn_atime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 144)
    }
}

#[inline]
pub unsafe fn tsk_fs_meta_get_ntfs_fn_ctime(meta: *const TskFsMeta) -> c_long {
    if meta.is_null() {
        0
    } else {
        read_field(meta as *const u8, 160)
    }
}

#[inline]
pub unsafe fn tsk_vs_part_get_start(part: *const TskVsPartInfo) -> u64 {
    if part.is_null() {
        0
    } else {
        read_field(part as *const u8, 32)
    }
}

#[inline]
pub unsafe fn tsk_vs_part_get_len(part: *const TskVsPartInfo) -> u64 {
    if part.is_null() {
        0
    } else {
        read_field(part as *const u8, 40)
    }
}

#[inline]
pub unsafe fn tsk_vs_part_get_flags(part: *const TskVsPartInfo) -> u8 {
    if part.is_null() {
        0
    } else {
        read_field::<u32>(part as *const u8, 64) as u8
    }
}

#[inline]
pub unsafe fn tsk_vs_part_get_desc(part: *const TskVsPartInfo) -> *const c_char {
    if part.is_null() {
        std::ptr::null()
    } else {
        read_field(part as *const u8, 48)
    }
}

pub fn last_tsk_error() -> String {
    unsafe {
        let ptr = tsk_error_get_errstr();
        if ptr.is_null() {
            return "unknown libtsk error".to_string();
        }
        std::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

pub fn reset_tsk_error() {
    unsafe {
        tsk_error_reset();
    }
}
