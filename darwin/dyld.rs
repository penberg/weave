use crate::mmap::MappedFile;
use std::fmt::Display;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

/// Main entry point for dynamic loading - parses Mach-O and sets up dyld structures
/// Returns the MachO and a set of host function addresses that were bound
pub fn load_machfile(file: MappedFile) -> Result<MachO, MachError> {
    let macho = MachO::open(file)?;
    let host_arch = crate::probe_host_arch();
    if macho.arch != host_arch {
        panic!(
            "cannot run binary for {} architecture on {} host",
            macho.arch, host_arch
        );
    }
    load_segments(&macho);
    process_dyld_info(&macho);
    match bind_symbols(&macho) {
        Ok(()) => (),
        Err(BindingError::UnresolvedSymbol(symbol)) => {
            eprintln!("FATAL ERROR: Cannot resolve symbol '{}'", symbol);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("FATAL ERROR: Symbol binding failed: {}", e);
            std::process::exit(1);
        }
    };
    Ok(macho)
}

fn process_dyld_info(macho: &MachO) {
    use tracing::trace;

    let dyld_info = macho.parse_dyld_info();

    debug!("Dynamic libraries: {}", dyld_info.dylibs.len());
    for (i, dylib) in dyld_info.dylibs.iter().enumerate() {
        debug!(
            "  [{}] {} (version: {})",
            i, dylib.name, dylib.current_version
        );
    }

    if let (Some(got_addr), Some(got_size)) =
        (dyld_info.got_section_addr, dyld_info.got_section_size)
    {
        trace!(
            "GOT section: 0x{:016x} (size: {} bytes, {} entries)",
            got_addr,
            got_size,
            got_size / 8
        );
    } else {
        debug!("No GOT section found");
    }

    trace!("Symbol imports: {}", dyld_info.fixups.len());
    for fixup in &dyld_info.fixups {
        trace!(
            "  {} -> lib_ordinal={}, GOT+0x{:x}",
            fixup.symbol_name, fixup.lib_ordinal, fixup.got_offset
        );
    }
}

// The base address of the Mach-O binary. We want to load the guest executable at higher addresses to avoid clashing with the Weave runtime.
const MACHO_BASE_ADDRESS: u64 = 0x0000000200000000;

#[derive(Debug, Error)]
pub enum MachError {
    #[error("not a Mach-O file")]
    NotMachO,
    #[error("unknown architecture: {0}")]
    UnknownArch(u32),
    #[error("unknown file type: {0}")]
    UnknownFileType(u32),
    #[error("not a PIE file")]
    NotPIE,
    #[error("text segment is missing")]
    MissingTextSegment,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Arch {
    AArch64,
    X86_64,
}

impl Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::AArch64 => write!(f, "AArch64"),
            Arch::X86_64 => write!(f, "X86_64"),
        }
    }
}

pub struct Segment {
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    /// Memory protection flags (libc::PROT_*)
    pub prot: libc::c_int,
}

pub struct Section {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DylibInfo {
    pub name: String,
    pub current_version: u32,
}

#[derive(Debug, Clone)]
pub struct ChainedFixup {
    pub lib_ordinal: u32,
    pub symbol_name: String,
    pub got_offset: u64, // Offset within GOT section
}

#[derive(Debug, Clone)]
pub struct DyldInfo {
    pub dylibs: Vec<DylibInfo>,
    pub fixups: Vec<ChainedFixup>,
    pub got_section_addr: Option<u64>,
    pub got_section_size: Option<u64>,
}

pub struct MachO {
    pub arch: Arch,
    pub entry_point: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dyld_info: DyldInfo,
    pub file: MappedFile,
}

impl MachO {
    pub fn open(file: MappedFile) -> Result<MachO, MachError> {
        parse_macho(file)
    }

    pub fn parse_dyld_info(&self) -> &DyldInfo {
        &self.dyld_info
    }
}

fn load_segments(macho: &MachO) {
    let fd = macho.file.fd;
    for segment in &macho.segments {
        debug!(
            "Loading segment {} at 0x{:016x} ({} bytes) prot={:x}",
            segment.segname, segment.vmaddr, segment.vmsize, segment.prot
        );

        // Skip __PAGEZERO - it's a guard region that shouldn't be mapped
        if segment.segname == "__PAGEZERO" {
            continue;
        }

        let prot = segment.prot & !libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_FIXED;
        let data = unsafe {
            libc::mmap(
                segment.vmaddr as *mut libc::c_void,
                segment.vmsize as usize,
                prot,
                flags,
                fd,
                segment.fileoff as libc::off_t,
            )
        };
        if data == libc::MAP_FAILED {
            error!("Failed to map segment: {}", std::io::Error::last_os_error());
        }
    }
}

#[derive(Debug)]
pub enum MachOFileType {
    Executable,
}

const MACHO_MAGIC: u32 = 0xfeedfacf;
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;
const MH_PIE: u32 = 0x00200000;

#[repr(C)]
#[derive(Debug)]
struct mach_header_64 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Debug)]
struct fat_header {
    magic: u32,
    nfat_arch: u32,
}

#[repr(C)]
#[derive(Debug)]
struct fat_arch {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    align: u32,
}

fn parse_macho(mut file: MappedFile) -> Result<MachO, MachError> {
    if file.data.len() < std::mem::size_of::<mach_header_64>() {
        return Err(MachError::NotMachO);
    }

    // Check for fat binary first
    let magic = unsafe { std::ptr::read(file.data.as_ptr() as *const u32) };
    let mut _offset = 0usize;

    if magic == FAT_MAGIC || magic == FAT_CIGAM {
        // This is a fat binary, need to extract the correct architecture
        debug!("Detected universal binary, extracting correct architecture");

        let fat_header = unsafe { std::ptr::read(file.data.as_ptr() as *const fat_header) };
        let nfat_arch = if magic == FAT_CIGAM {
            // Big-endian, need to swap
            fat_header.nfat_arch.swap_bytes()
        } else {
            fat_header.nfat_arch
        };

        // Look for arm64 architecture (0x100000c)
        const CPU_TYPE_ARM64: u32 = 0x100000c;
        let mut found_offset = None;
        let mut found_size = None;

        for i in 0..nfat_arch {
            let arch_offset =
                std::mem::size_of::<fat_header>() + (i as usize) * std::mem::size_of::<fat_arch>();
            let fat_arch =
                unsafe { std::ptr::read(file.data.as_ptr().add(arch_offset) as *const fat_arch) };

            let cputype = if magic == FAT_CIGAM {
                fat_arch.cputype.swap_bytes()
            } else {
                fat_arch.cputype
            };

            if cputype == CPU_TYPE_ARM64 {
                found_offset = Some(if magic == FAT_CIGAM {
                    fat_arch.offset.swap_bytes() as usize
                } else {
                    fat_arch.offset as usize
                });
                found_size = Some(if magic == FAT_CIGAM {
                    fat_arch.size.swap_bytes() as usize
                } else {
                    fat_arch.size as usize
                });
                break;
            }
        }

        if let (Some(arch_offset), Some(arch_size)) = (found_offset, found_size) {
            debug!(
                "Found ARM64 slice at offset 0x{:x}, size 0x{:x}",
                arch_offset, arch_size
            );
            // Create a new MappedFile view for just the ARM64 slice
            // We'll adjust the data slice to point to the correct architecture
            _offset = arch_offset;
            file.data = &file.data[arch_offset..arch_offset + arch_size];
        } else {
            return Err(MachError::UnknownArch(0x100000c));
        }
    }

    // Now parse the actual Mach-O (either direct or from fat slice)
    let header = unsafe { std::ptr::read(file.data.as_ptr() as *const mach_header_64) };
    if header.magic != MACHO_MAGIC {
        return Err(MachError::NotMachO);
    }
    if (header.flags & MH_PIE) == 0 {
        return Err(MachError::NotPIE);
    }
    let arch = match header.cputype & !0x00000001 {
        0x100000c => Arch::AArch64,
        _ => return Err(MachError::UnknownArch(header.cputype)),
    };
    match header.filetype {
        0x2 => MachOFileType::Executable,
        _ => return Err(MachError::UnknownFileType(header.filetype)),
    };
    let (entry_point, segments, sections, dyld_info) = parse_load_cmds(&file, header.ncmds)?;
    Ok(MachO {
        arch,
        entry_point,
        segments,
        sections,
        dyld_info,
        file,
    })
}

#[derive(Debug)]
#[repr(C)]
struct load_command {
    cmd: u32,
    cmdsize: u32,
}

const LC_REQ_DYLD: u32 = 0x80000000;

const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_SOURCE_VERSION: u32 = 0x2a;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

#[derive(Debug)]
#[repr(C)]
struct segment_command_64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
}

#[derive(Debug)]
#[repr(C)]
struct entry_point_command {
    cmd: u32,
    cmdsize: u32,
    entryoff: u64,
    stacksize: u64,
}

#[derive(Debug)]
#[repr(C)]
struct section_64 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

#[derive(Debug)]
#[repr(C)]
struct dylib_command {
    cmd: u32,
    cmdsize: u32,
    dylib_name_offset: u32,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
}

#[derive(Debug)]
#[repr(C)]
struct linkedit_data_command {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

#[derive(Debug)]
#[repr(C)]
struct dyld_info_command {
    cmd: u32,
    cmdsize: u32,
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}

#[derive(Debug)]
#[repr(C)]
struct dyld_chained_fixups_header {
    fixups_version: u32,
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_format: u32,
}

fn parse_load_cmds(
    file: &MappedFile,
    ncmds: u32,
) -> Result<(u64, Vec<Segment>, Vec<Section>, DyldInfo), MachError> {
    let mut entry_point = 0;
    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut dyld_info = DyldInfo {
        dylibs: Vec::new(),
        fixups: Vec::new(),
        got_section_addr: None,
        got_section_size: None,
    };
    let mut offset = std::mem::size_of::<mach_header_64>();
    for _ in 0..ncmds {
        let cmd = unsafe { std::ptr::read(file.data.as_ptr().add(offset) as *const load_command) };
        match cmd.cmd {
            LC_SYMTAB => { /* ignore */ }
            LC_DYSYMTAB => { /* ignore */ }
            LC_LOAD_DYLIB => {
                let dylib_cmd = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const dylib_command)
                };

                // Extract the library name string
                let name_offset = offset + dylib_cmd.dylib_name_offset as usize;
                let name_start = file.data.as_ptr();
                let name_bytes = unsafe {
                    let mut len = 0;
                    let mut ptr = name_start.add(name_offset);
                    while *ptr != 0 && len < 256 {
                        // Safety limit
                        len += 1;
                        ptr = ptr.add(1);
                    }
                    std::slice::from_raw_parts(name_start.add(name_offset), len)
                };

                if let Ok(name) = std::str::from_utf8(name_bytes) {
                    trace!(
                        "Found dylib: {} (version: {})",
                        name, dylib_cmd.current_version
                    );
                    dyld_info.dylibs.push(DylibInfo {
                        name: name.to_string(),
                        current_version: dylib_cmd.current_version,
                    });
                } else {
                    warn!("Failed to parse dylib name at offset {}", name_offset);
                }
            }
            LC_LOAD_DYLINKER => { /* ignore */ }
            LC_SEGMENT_64 => {
                let segment = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const segment_command_64)
                };
                // Translate Mach-O VM protection flags to libc PROT_ flags
                const VM_PROT_READ: u32 = 0x1;
                const VM_PROT_WRITE: u32 = 0x2;
                const VM_PROT_EXECUTE: u32 = 0x4;

                let mut prot: libc::c_int = 0;
                if (segment.initprot & VM_PROT_READ) != 0 {
                    prot |= libc::PROT_READ;
                }
                if (segment.initprot & VM_PROT_WRITE) != 0 {
                    prot |= libc::PROT_WRITE;
                }
                if (segment.initprot & VM_PROT_EXECUTE) != 0 {
                    prot |= libc::PROT_EXEC;
                }

                let segname = String::from_utf8_lossy(&segment.segname)
                    .trim_end_matches('\0')
                    .to_string();

                // Don't relocate __PAGEZERO - it needs to stay at address 0
                let vmaddr = if segname == "__PAGEZERO" {
                    segment.vmaddr
                } else {
                    segment.vmaddr + MACHO_BASE_ADDRESS
                };

                segments.push(Segment {
                    segname,
                    vmaddr,
                    vmsize: segment.vmsize,
                    fileoff: segment.fileoff,
                    filesize: segment.filesize,
                    prot,
                });

                // Parse sections within this segment
                let sections_offset = offset + std::mem::size_of::<segment_command_64>();
                for i in 0..segment.nsects {
                    let section_offset =
                        sections_offset + i as usize * std::mem::size_of::<section_64>();
                    let section = unsafe {
                        std::ptr::read(file.data.as_ptr().add(section_offset) as *const section_64)
                    };

                    let sectname = String::from_utf8_lossy(&section.sectname)
                        .trim_end_matches('\0')
                        .to_string();
                    let segname = String::from_utf8_lossy(&section.segname)
                        .trim_end_matches('\0')
                        .to_string();

                    let relocated_addr = section.addr + MACHO_BASE_ADDRESS;

                    // Detect GOT section
                    if sectname == "__got" {
                        debug!(
                            "Found __got section at 0x{:016x}, size {}",
                            relocated_addr, section.size
                        );
                        dyld_info.got_section_addr = Some(relocated_addr);
                        dyld_info.got_section_size = Some(section.size);
                    }

                    sections.push(Section {
                        sectname,
                        segname,
                        addr: relocated_addr,
                        size: section.size,
                    });
                }
            }
            LC_UUID => { /* ignore */ }
            LC_FUNCTION_STARTS => { /* ignore */ }
            LC_DATA_IN_CODE => { /* ignore */ }
            LC_SOURCE_VERSION => { /* ignore */ }
            LC_CODE_SIGNATURE => { /* ignore */ }
            LC_BUILD_VERSION => { /* ignore */ }
            LC_MAIN => {
                let main = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const entry_point_command)
                };
                entry_point = main.entryoff;
            }
            LC_DYLD_EXPORTS_TRIE => { /* ignore */ }
            LC_DYLD_INFO_ONLY => {
                let dyld_info_cmd = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const dyld_info_command)
                };

                debug!(
                    "Found dyld info at bind_off={}, bind_size={}",
                    dyld_info_cmd.bind_off, dyld_info_cmd.bind_size
                );

                // Parse the binding information
                if dyld_info_cmd.bind_off > 0 && dyld_info_cmd.bind_size > 0 {
                    let bind_data = &file.data[dyld_info_cmd.bind_off as usize
                        ..(dyld_info_cmd.bind_off + dyld_info_cmd.bind_size) as usize];
                    if let Ok(parsed_fixups) = parse_dyld_bind_info(bind_data) {
                        dyld_info.fixups.extend(parsed_fixups);
                    } else {
                        warn!("Failed to parse dyld bind info");
                    }
                }
            }
            LC_DYLD_CHAINED_FIXUPS => {
                let fixups_cmd = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const linkedit_data_command)
                };

                debug!(
                    "Found chained fixups at offset {}, size {}",
                    fixups_cmd.dataoff, fixups_cmd.datasize
                );

                // Parse the chained fixups data
                let fixups_data = &file.data[fixups_cmd.dataoff as usize
                    ..(fixups_cmd.dataoff + fixups_cmd.datasize) as usize];
                if let Ok(parsed_fixups) = parse_chained_fixups(fixups_data) {
                    dyld_info.fixups.extend(parsed_fixups);
                } else {
                    warn!("Failed to parse chained fixups data");
                }
            }
            cmd => {
                warn!("Unknown Mach-O load command: {:x}", cmd);
            }
        }
        offset += cmd.cmdsize as usize;
    }
    let text_segment = segments
        .iter()
        .find(|s| s.segname == "__TEXT")
        .ok_or(MachError::MissingTextSegment)?;
    entry_point += text_segment.vmaddr;
    Ok((entry_point, segments, sections, dyld_info))
}

fn parse_chained_fixups(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
    if data.len() < std::mem::size_of::<dyld_chained_fixups_header>() {
        return Err("Chained fixups data too small".to_string());
    }

    let header = unsafe { std::ptr::read(data.as_ptr() as *const dyld_chained_fixups_header) };

    debug!(
        "Chained fixups header: version={}, imports_count={}, imports_offset={}, symbols_offset={}",
        header.fixups_version, header.imports_count, header.imports_offset, header.symbols_offset
    );

    let mut fixups = Vec::new();

    // Parse imports (simplified for DYLD_CHAINED_IMPORT format)
    if header.imports_format == 1 {
        // DYLD_CHAINED_IMPORT
        for i in 0..header.imports_count {
            let import_offset = header.imports_offset as usize + (i * 4) as usize;
            if import_offset + 4 > data.len() {
                warn!("Import {} out of bounds", i);
                continue;
            }

            let import_value = u32::from_le_bytes([
                data[import_offset],
                data[import_offset + 1],
                data[import_offset + 2],
                data[import_offset + 3],
            ]);

            // Extract fields from packed import value
            let lib_ordinal = import_value & 0xff;
            let name_offset = (import_value >> 9) & 0x7fffff;

            // Extract symbol name
            let symbol_offset = header.symbols_offset as usize + name_offset as usize;
            if symbol_offset < data.len() {
                let symbol_bytes = &data[symbol_offset..];
                let symbol_name = if let Some(null_pos) = symbol_bytes.iter().position(|&b| b == 0)
                {
                    String::from_utf8_lossy(&symbol_bytes[..null_pos]).to_string()
                } else {
                    String::from_utf8_lossy(symbol_bytes).to_string()
                };

                debug!(
                    "Import {}: lib_ordinal={}, symbol={}",
                    i, lib_ordinal, symbol_name
                );

                // For now, assume GOT entries are sequential at offset i*8
                // This is a simplification - real parsing would use the starts table
                fixups.push(ChainedFixup {
                    lib_ordinal,
                    symbol_name,
                    got_offset: i as u64 * 8,
                });
            }
        }
    } else {
        warn!("Unsupported imports format: {}", header.imports_format);
    }

    Ok(fixups)
}

#[derive(Debug)]
pub enum BindingError {
    UnresolvedSymbol(String),
    InvalidGotAddress,
    MemoryProtection,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::UnresolvedSymbol(sym) => write!(f, "Unresolved symbol: {}", sym),
            BindingError::InvalidGotAddress => write!(f, "Invalid GOT address"),
            BindingError::MemoryProtection => write!(f, "Memory protection error"),
        }
    }
}

impl std::error::Error for BindingError {}

/// Symbol resolution to our libc implementations  
fn resolve_symbol(symbol_name: &str) -> Result<u64, BindingError> {
    match symbol_name {
        "_printf" => Ok(libc::printf as *const () as u64),
        "_rand" => Ok(crate::libc::rand::weave_rand as *const () as u64),
        "_srand" => Ok(crate::libc::rand::weave_srand as *const () as u64),
        "_time" => Ok(crate::libc::time::weave_time as *const () as u64),
        _ => Err(BindingError::UnresolvedSymbol(symbol_name.to_string())),
    }
}

/// Read a ULEB128 encoded unsigned integer, returns (value, bytes_consumed)
fn read_uleb128(data: &[u8], start_index: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut bytes_consumed = 0;

    while start_index + bytes_consumed < data.len() {
        let byte = data[start_index + bytes_consumed];
        bytes_consumed += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, bytes_consumed));
        }

        shift += 7;
        if shift >= 64 {
            return Err("ULEB128 value too large".to_string());
        }
    }

    Err("Unexpected end of data while reading ULEB128".to_string())
}

/// Parse dyld bind info opcodes from LC_DYLD_INFO_ONLY
fn parse_dyld_bind_info(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
    let mut fixups = Vec::new();
    let mut i = 0;

    let mut lib_ordinal = 0u8;
    let mut symbol_name = String::new();
    let mut segment_offset = 0u64;

    while i < data.len() {
        let opcode = data[i];
        let immediate = opcode & 0x0F;
        let command = opcode & 0xF0;

        trace!("Parsing opcode 0x{:02x} at index {}", opcode, i);
        match command {
            0x00 => {
                // BIND_OPCODE_DONE
                break;
            }
            0x10 => {
                // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                lib_ordinal = immediate;
            }
            0x20 => {
                // BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
                match read_uleb128(data, i + 1) {
                    Ok((ordinal, bytes_consumed)) => {
                        lib_ordinal = ordinal as u8;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 ordinal".to_string()),
                }
            }
            0x30 => {
                // BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
                // Handle special ordinals (usually negative values for self-references)
                lib_ordinal = immediate;
            }
            0x40 => {
                // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                i += 1;
                // Read null-terminated string
                let start = i;
                while i < data.len() && data[i] != 0 {
                    i += 1;
                }
                if i < data.len() {
                    symbol_name = String::from_utf8_lossy(&data[start..i]).to_string();
                }
            }
            0x50 => { // BIND_OPCODE_SET_TYPE_IMM
                // We'll ignore bind type for now (usually BIND_TYPE_POINTER = 1)
            }
            0x60 => {
                // BIND_OPCODE_SET_ADDEND_SLEB
                i += 1;
            }
            0x70 => {
                // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                match read_uleb128(data, i + 1) {
                    Ok((offset, bytes_consumed)) => {
                        segment_offset = offset;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 segment offset".to_string()),
                }
            }
            0x80 => {
                // BIND_OPCODE_ADD_ADDR_ULEB
                match read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset += addr_add;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 address add".to_string()),
                }
            }
            0x90 => {
                // BIND_OPCODE_DO_BIND
                // Create a fixup entry - lib_ordinal validation happens during symbol binding
                if !symbol_name.is_empty() {
                    trace!("Creating fixup for symbol: {}", symbol_name);
                    fixups.push(ChainedFixup {
                        symbol_name: symbol_name.clone(),
                        lib_ordinal: lib_ordinal as u32,
                        got_offset: segment_offset,
                    });
                }
                segment_offset += 8; // Advance to next pointer slot
            }
            0xA0 => {
                // BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
                // Bind and advance by specified amount
                if !symbol_name.is_empty() {
                    fixups.push(ChainedFixup {
                        symbol_name: symbol_name.clone(),
                        lib_ordinal: lib_ordinal as u32,
                        got_offset: segment_offset,
                    });
                }
                match read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset += addr_add;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 address add".to_string()),
                }
            }
            0xB0 => {
                // BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
                // Bind and advance by immediate * pointer size
                if !symbol_name.is_empty() {
                    fixups.push(ChainedFixup {
                        symbol_name: symbol_name.clone(),
                        lib_ordinal: lib_ordinal as u32,
                        got_offset: segment_offset,
                    });
                }
                segment_offset += (immediate as u64) * 8;
            }
            0xC0 => {
                // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                // Bind multiple times with skip
                let (count, count_bytes) = match read_uleb128(data, i + 1) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 count".to_string()),
                };
                let (skip, skip_bytes) = match read_uleb128(data, i + 1 + count_bytes) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 skip".to_string()),
                };

                for _ in 0..count {
                    if !symbol_name.is_empty() {
                        fixups.push(ChainedFixup {
                            symbol_name: symbol_name.clone(),
                            lib_ordinal: lib_ordinal as u32,
                            got_offset: segment_offset,
                        });
                    }
                    segment_offset += skip as u64;
                }
                i += count_bytes + skip_bytes; // Skip the count and skip bytes
            }
            _ => {
                warn!("Unknown bind opcode: 0x{:02x}", opcode);
            }
        }
        i += 1;
    }
    Ok(fixups)
}

/// Symbol binding at load time (like real dyld)
/// Returns a set of host function addresses that were bound
pub fn bind_symbols(macho: &MachO) -> Result<(), BindingError> {
    let dyld_info = macho.parse_dyld_info();

    // Only proceed if we have both GOT section and fixups
    let got_base_addr = match dyld_info.got_section_addr {
        Some(addr) => addr,
        None => {
            trace!("No GOT section found, skipping symbol binding");
            return Ok(());
        }
    };

    if dyld_info.fixups.is_empty() {
        trace!("No symbol fixups found, skipping symbol binding");
        return Ok(());
    }

    debug!("Binding {} symbols at load time", dyld_info.fixups.len());

    for fixup in &dyld_info.fixups {
        match resolve_symbol(&fixup.symbol_name) {
            Ok(symbol_addr) => {
                let got_entry_addr = got_base_addr + fixup.got_offset;
                debug!(
                    "Binding {} -> 0x{:016x} at GOT+0x{:x}",
                    fixup.symbol_name, symbol_addr, fixup.got_offset
                );

                // Patch GOT entry with resolved address
                unsafe {
                    *(got_entry_addr as *mut u64) = symbol_addr;
                }
            }
            Err(BindingError::UnresolvedSymbol(_)) => {
                // Error out immediately on unresolved symbols
                error!("FATAL: Unresolved symbol: {}", fixup.symbol_name);
                return Err(BindingError::UnresolvedSymbol(fixup.symbol_name.clone()));
            }
            Err(e) => return Err(e),
        }
    }

    // Flush instruction cache for the GOT region
    if let Some(got_size) = dyld_info.got_section_size {
        crate::runtime::flush_icache_range(got_base_addr as *const u8, got_size as usize);
        debug!(
            "Flushed icache for GOT region: 0x{:016x} ({} bytes)",
            got_base_addr, got_size
        );
    }

    Ok(())
}
