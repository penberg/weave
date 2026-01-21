//! Mach-O binary format structures and constants.
//!
//! This module contains the C FFI structures and constants used for parsing
//! Mach-O binaries on Darwin/macOS. These are shared between the dyld loader
//! and the dyld shared cache discovery code.

// Mach-O magic numbers
pub const MACHO_MAGIC: u32 = 0xfeedfacf; // 64-bit Mach-O
pub const FAT_MAGIC: u32 = 0xcafebabe; // Fat binary (big-endian)
pub const FAT_CIGAM: u32 = 0xbebafeca; // Fat binary (little-endian)

// Mach-O flags
pub const MH_PIE: u32 = 0x00200000; // Position Independent Executable

// Load command types
pub const LC_REQ_DYLD: u32 = 0x80000000;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

// Chained fixup pointer format constants
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 7;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 8;

/// Mach-O 64-bit header
#[derive(Debug)]
#[repr(C)]
pub struct mach_header_64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

/// Fat (universal) binary header
#[derive(Debug)]
#[repr(C)]
pub struct fat_header {
    pub magic: u32,
    pub nfat_arch: u32,
}

/// Fat binary architecture entry
#[derive(Debug)]
#[repr(C)]
pub struct fat_arch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

/// Generic load command header
#[derive(Debug)]
#[repr(C)]
pub struct load_command {
    pub cmd: u32,
    pub cmdsize: u32,
}

/// 64-bit segment load command
#[derive(Debug)]
#[repr(C)]
pub struct segment_command_64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

/// 64-bit section within a segment
#[derive(Debug)]
#[repr(C)]
pub struct section_64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

/// Entry point load command (LC_MAIN)
#[derive(Debug)]
#[repr(C)]
pub struct entry_point_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

/// Dynamic library load command (LC_LOAD_DYLIB)
#[derive(Debug)]
#[repr(C)]
pub struct dylib_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dylib_name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

/// LinkedEdit data command (LC_FUNCTION_STARTS, LC_DATA_IN_CODE, etc.)
#[derive(Debug)]
#[repr(C)]
pub struct linkedit_data_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

/// Dynamic linker info command (LC_DYLD_INFO_ONLY)
#[derive(Debug)]
#[repr(C)]
pub struct dyld_info_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Chained fixups header (LC_DYLD_CHAINED_FIXUPS)
#[derive(Debug)]
#[repr(C)]
pub struct dyld_chained_fixups_header {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32,
    pub symbols_format: u32,
}

/// Chained fixup starts in image
#[derive(Debug)]
#[repr(C)]
pub struct dyld_chained_starts_in_image {
    pub seg_count: u32,
    // seg_info_offset array follows - offsets to dyld_chained_starts_in_segment for each segment
}

/// Chained fixup starts in segment
#[derive(Debug)]
#[repr(C)]
pub struct dyld_chained_starts_in_segment {
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: u16,
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
    // page_start array follows
}

/// Mach-O file type
#[derive(Debug)]
pub enum MachOFileType {
    Executable,
}
