use crate::mmap::MappedFile;
use std::fmt::Display;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

pub mod bind;
pub mod cache;
pub mod chained;
pub mod dlopen;
pub mod exports;
pub mod macho;
pub mod tlv;

pub use bind::RebaseEntry;
pub use dlopen::{dlclose_impl, dlerror_impl, dlopen_impl, dlsym_impl};

use macho::*;

/// Main entry point for dynamic loading - parses Mach-O and sets up dyld structures
/// Returns the MachO and a set of host function addresses that were bound
pub fn load_machfile(file: MappedFile) -> Result<MachO, crate::ObjectFormatError> {
    let macho = MachO::open(file)?;
    let host_arch = crate::probe_host_arch();
    if macho.arch != host_arch {
        return Err(crate::ObjectFormatError::UnsupportedArch {
            binary_arch: macho.arch.to_string(),
            host_arch: host_arch.to_string(),
        });
    }
    load_segments(&macho, 0);
    apply_rebases(&macho, 0);
    chained::apply_chained_rebases(&macho, 0);
    process_dyld_info(&macho);
    bind_symbols(&macho, 0)?;
    // Initialize TLV (Thread Local Variable) descriptors
    tlv::initialize_tlv_descriptors(&macho, 0);
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

        // Load the dynamic library so its symbols are available
        let c_name = match std::ffi::CString::new(dylib.name.as_str()) {
            Ok(s) => s,
            Err(_) => {
                warn!("Failed to create CString for dylib: {}", dylib.name);
                continue;
            }
        };
        let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if handle.is_null() {
            // This is not necessarily an error - some system libraries may already be loaded
            // or may not be found by this path
            trace!("dlopen failed for {}", dylib.name);
        } else {
            trace!("Loaded library: {}", dylib.name);
        }
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
            "  {} -> lib_ordinal={}, segment[{}]+0x{:x}",
            fixup.symbol_name, fixup.lib_ordinal, fixup.segment_index, fixup.segment_offset
        );
    }
}

// The base address of the Mach-O binary. We want to load the guest executable at higher addresses to avoid clashing with the Weave runtime.
pub const MACHO_BASE_ADDRESS: u64 = 0x0000000200000000;

#[derive(Debug, Error)]
pub enum MachError {
    #[error("not a Mach-O file")]
    NotMachO,
    #[error("unknown architecture: {0}")]
    UnknownArch(u32),
    #[error("unknown file type: {0}")]
    UnknownFileType(u32),
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
    pub segment_index: u8,   // Segment index for segment-relative fixups
    pub segment_offset: u64, // Offset within segment
}


#[derive(Debug, Clone)]
pub struct DyldInfo {
    pub dylibs: Vec<DylibInfo>,
    pub fixups: Vec<ChainedFixup>,
    pub rebases: Vec<RebaseEntry>,
    pub got_section_addr: Option<u64>,
    pub got_section_size: Option<u64>,
    /// Raw exports trie data (from LC_DYLD_EXPORTS_TRIE)
    pub exports_trie: Vec<u8>,
    /// Raw chained fixups data (from LC_DYLD_CHAINED_FIXUPS)
    pub chained_fixups_data: Vec<u8>,
}

pub struct MachO {
    pub arch: Arch,
    pub entry_point: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dyld_info: DyldInfo,
    pub file: MappedFile,
    /// Offset of the Mach-O slice within a fat/universal binary (0 for thin binaries)
    pub fat_offset: usize,
}

impl MachO {
    pub fn open(file: MappedFile) -> Result<MachO, crate::ObjectFormatError> {
        parse_macho(file)
    }

    pub fn parse_dyld_info(&self) -> &DyldInfo {
        &self.dyld_info
    }
}

/// Map Mach-O segments into memory.
///
/// The slide parameter adjusts where segments are loaded relative to their
/// stored vmaddr. For the main executable, slide=0 since vmaddrs already
/// have MACHO_BASE_ADDRESS baked in. For dlopen'd libraries, slide is
/// computed to place the library at a different base address.
pub(crate) fn load_segments(macho: &MachO, slide: i64) {
    let fd = macho.file.fd;
    for segment in &macho.segments {
        // Skip __PAGEZERO - it's a guard region that shouldn't be mapped
        if segment.segname == "__PAGEZERO" {
            continue;
        }

        let target_addr = (segment.vmaddr as i64 + slide) as u64;
        debug!(
            "Loading segment {} at 0x{:016x} (vmsize={} filesize={}) prot={:x}",
            segment.segname, target_addr, segment.vmsize, segment.filesize, segment.prot
        );

        let prot = segment.prot & !libc::PROT_EXEC;

        // Handle zerofill (BSS): when vmsize > filesize, the extra bytes must be zeroed.
        // We handle this by:
        // 1. First mapping the entire vmsize as anonymous memory (zeroed)
        // 2. Then mapping the file data over the first filesize bytes
        if segment.vmsize > segment.filesize {
            // Map zeroed anonymous memory for the entire segment
            let anon_data = unsafe {
                libc::mmap(
                    target_addr as *mut libc::c_void,
                    segment.vmsize as usize,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if anon_data == libc::MAP_FAILED {
                error!(
                    "Failed to map anonymous memory for segment: {}",
                    std::io::Error::last_os_error()
                );
                continue;
            }

            // If there's file data, map it over the beginning
            if segment.filesize > 0 {
                let file_offset = segment.fileoff as usize + macho.fat_offset;
                let file_data = unsafe {
                    libc::mmap(
                        target_addr as *mut libc::c_void,
                        segment.filesize as usize,
                        prot,
                        libc::MAP_PRIVATE | libc::MAP_FIXED,
                        fd,
                        file_offset as libc::off_t,
                    )
                };
                if file_data == libc::MAP_FAILED {
                    error!(
                        "Failed to map file data for segment: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        } else {
            // No zerofill - just map the file data directly
            let flags = libc::MAP_PRIVATE | libc::MAP_FIXED;
            // For fat/universal binaries, segment.fileoff is relative to the Mach-O slice,
            // but the fd refers to the entire fat file, so we need to add fat_offset
            let file_offset = segment.fileoff as usize + macho.fat_offset;
            let data = unsafe {
                libc::mmap(
                    target_addr as *mut libc::c_void,
                    segment.vmsize as usize,
                    prot,
                    flags,
                    fd,
                    file_offset as libc::off_t,
                )
            };
            if data == libc::MAP_FAILED {
                error!("Failed to map segment: {}", std::io::Error::last_os_error());
            }
        }
    }
}

/// Apply rebase fixups to adjust internal pointers for relocation.
///
/// The segment_slide parameter adjusts where we read/write rebase entries.
/// For main executable, segment_slide=0. For dlopen'd libraries, it's non-zero.
pub(crate) fn apply_rebases(macho: &MachO, segment_slide: i64) {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.rebases.is_empty() {
        return;
    }

    debug!("Applying {} rebase fixups", dyld_info.rebases.len());

    // Internal pointers in the file don't have MACHO_BASE_ADDRESS, so we add it
    let pointer_slide = MACHO_BASE_ADDRESS;

    for rebase in &dyld_info.rebases {
        let segment = match macho.segments.get(rebase.segment_index as usize) {
            Some(seg) => seg,
            None => {
                warn!("Invalid segment index {} for rebase", rebase.segment_index);
                continue;
            }
        };

        let entry_addr = (segment.vmaddr as i64 + segment_slide) as u64 + rebase.segment_offset;

        // Read the current pointer value, add the slide, and write it back
        unsafe {
            let ptr = entry_addr as *mut u64;
            let old_value = *ptr;
            let new_value = old_value.wrapping_add(pointer_slide);
            *ptr = new_value;
            trace!(
                "Rebase at 0x{:x}: 0x{:x} -> 0x{:x}",
                entry_addr, old_value, new_value
            );
        }
    }

    debug!(
        "Applied {} rebase fixups with pointer_slide 0x{:x}",
        dyld_info.rebases.len(),
        pointer_slide
    );
}

fn parse_macho(mut file: MappedFile) -> Result<MachO, crate::ObjectFormatError> {
    if file.data.len() < std::mem::size_of::<mach_header_64>() {
        return Err(MachError::NotMachO.into());
    }

    // Check for fat binary first
    let magic = unsafe { std::ptr::read(file.data.as_ptr() as *const u32) };
    let mut fat_offset = 0usize;

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
            // Store the fat offset so we can adjust mmap calls later
            fat_offset = arch_offset;
            file.data = &file.data[arch_offset..arch_offset + arch_size];
        } else {
            return Err(MachError::UnknownArch(0x100000c).into());
        }
    }

    // Now parse the actual Mach-O (either direct or from fat slice)
    let header = unsafe { std::ptr::read(file.data.as_ptr() as *const mach_header_64) };
    if header.magic != MACHO_MAGIC {
        return Err(MachError::NotMachO.into());
    }
    let arch = match header.cputype & !0x00000001 {
        0x100000c => Arch::AArch64,
        _ => return Err(MachError::UnknownArch(header.cputype).into()),
    };
    // Check file type and PIE flag
    // Dynamic libraries (0x6) don't require PIE flag
    // Executables (0x2) require PIE
    match header.filetype {
        0x2 => {
            // Executable - require PIE
            if (header.flags & MH_PIE) == 0 {
                return Err(crate::ObjectFormatError::NotPIE);
            }
            MachOFileType::Executable
        }
        0x6 => {
            // Dynamic library - PIE not required
            MachOFileType::Executable // Use same variant for now
        }
        _ => return Err(MachError::UnknownFileType(header.filetype).into()),
    };
    let (entry_point, segments, sections, dyld_info) = parse_load_cmds(&file, header.ncmds)?;
    Ok(MachO {
        arch,
        entry_point,
        segments,
        sections,
        dyld_info,
        file,
        fat_offset,
    })
}

fn parse_load_cmds(
    file: &MappedFile,
    ncmds: u32,
) -> Result<(u64, Vec<Segment>, Vec<Section>, DyldInfo), crate::ObjectFormatError> {
    let mut entry_point = 0;
    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut dyld_info = DyldInfo {
        dylibs: Vec::new(),
        fixups: Vec::new(),
        rebases: Vec::new(),
        got_section_addr: None,
        got_section_size: None,
        exports_trie: Vec::new(),
        chained_fixups_data: Vec::new(),
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
            LC_DYLD_EXPORTS_TRIE => {
                let exports_cmd = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const linkedit_data_command)
                };

                debug!(
                    "Found exports trie at offset {}, size {}",
                    exports_cmd.dataoff, exports_cmd.datasize
                );

                // Save the raw exports trie data
                if exports_cmd.dataoff > 0 && exports_cmd.datasize > 0 {
                    let start = exports_cmd.dataoff as usize;
                    let end = start + exports_cmd.datasize as usize;
                    if end <= file.data.len() {
                        dyld_info.exports_trie = file.data[start..end].to_vec();
                    }
                }
            }
            LC_DYLD_INFO_ONLY => {
                let dyld_info_cmd = unsafe {
                    std::ptr::read(file.data.as_ptr().add(offset) as *const dyld_info_command)
                };

                debug!(
                    "Found dyld info at rebase_off={}, rebase_size={}, bind_off={}, bind_size={}, lazy_bind_off={}, lazy_bind_size={}",
                    dyld_info_cmd.rebase_off,
                    dyld_info_cmd.rebase_size,
                    dyld_info_cmd.bind_off,
                    dyld_info_cmd.bind_size,
                    dyld_info_cmd.lazy_bind_off,
                    dyld_info_cmd.lazy_bind_size
                );

                // Parse the rebase information
                if dyld_info_cmd.rebase_off > 0 && dyld_info_cmd.rebase_size > 0 {
                    let rebase_data = &file.data[dyld_info_cmd.rebase_off as usize
                        ..(dyld_info_cmd.rebase_off + dyld_info_cmd.rebase_size) as usize];
                    if let Ok(parsed_rebases) = bind::parse_dyld_rebase_info(rebase_data) {
                        dyld_info.rebases.extend(parsed_rebases);
                    } else {
                        warn!("Failed to parse dyld rebase info");
                    }
                }

                // Parse the binding information (eager binding)
                if dyld_info_cmd.bind_off > 0 && dyld_info_cmd.bind_size > 0 {
                    let bind_data = &file.data[dyld_info_cmd.bind_off as usize
                        ..(dyld_info_cmd.bind_off + dyld_info_cmd.bind_size) as usize];
                    if let Ok(parsed_fixups) = bind::parse_dyld_bind_info(bind_data) {
                        dyld_info.fixups.extend(parsed_fixups);
                    } else {
                        warn!("Failed to parse dyld bind info");
                    }
                }

                // Parse the lazy binding information (resolve lazily-bound symbols eagerly)
                if dyld_info_cmd.lazy_bind_off > 0 && dyld_info_cmd.lazy_bind_size > 0 {
                    let lazy_bind_data = &file.data[dyld_info_cmd.lazy_bind_off as usize
                        ..(dyld_info_cmd.lazy_bind_off + dyld_info_cmd.lazy_bind_size) as usize];
                    if let Ok(parsed_fixups) = bind::parse_dyld_lazy_bind_info(lazy_bind_data) {
                        dyld_info.fixups.extend(parsed_fixups);
                    } else {
                        warn!("Failed to parse dyld lazy bind info");
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

                // Store the raw data for later processing of rebases
                dyld_info.chained_fixups_data = fixups_data.to_vec();

                if let Ok(parsed_fixups) = chained::parse_chained_fixups(fixups_data, &segments) {
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
        .ok_or(crate::ObjectFormatError::MissingTextSegment)?;
    entry_point += text_segment.vmaddr;
    Ok((entry_point, segments, sections, dyld_info))
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

/// Deterministic stack canary value for stack protection
static STACK_CHK_GUARD: u64 = 0x00000000deadbeef;

// External libc symbols
// Note: Math functions are resolved from shared cache for binary translation (see cache.rs)
unsafe extern "C" {
    static __stderrp: *mut libc::FILE;
    static __stdoutp: *mut libc::FILE;
    static mach_task_self_: libc::c_uint;
}

/// Stub for dyld_stub_binder - this is called for lazy binding but we bind everything at load time
#[unsafe(no_mangle)]
extern "C" fn dyld_stub_binder() {
    panic!("dyld_stub_binder called - should not happen with eager binding");
}

/// Symbol resolution based on the source library.
///
/// Resolution order:
/// 1. Weave-provided overrides (for determinism: rand, srand, time, etc.)
/// 2. Special symbols (stack guard, TLV bootstrap, etc.)
/// 3. If from a shared cache library (libSystem), look up in the shared cache
/// 4. Error if not found (no dlsym fallback - we never want to execute untranslated code)
fn resolve_symbol(symbol_name: &str, dylib_name: Option<&str>) -> Result<u64, BindingError> {
    // 1. Check Weave-provided overrides first (for determinism)
    if let Some(addr) = crate::symbols::lookup(symbol_name) {
        return Ok(addr);
    }

    // 2. Check special symbols
    match symbol_name {
        "___stack_chk_guard" => return Ok(&STACK_CHK_GUARD as *const u64 as u64),
        "___stderrp" => return Ok(unsafe { &__stderrp as *const _ as u64 }),
        "___stdoutp" => return Ok(unsafe { &__stdoutp as *const _ as u64 }),
        "__tlv_bootstrap" => return Ok(tlv::weave_tlv_get_addr_wrapper as *const () as u64),
        "_mach_task_self_" => return Ok(unsafe { &mach_task_self_ as *const _ as u64 }),
        "dyld_stub_binder" => return Ok(dyld_stub_binder as *const () as u64),
        _ => {}
    }

    // 3. If from a shared cache library, look up in shared cache
    if let Some(lib) = dylib_name
        && lib.contains("libSystem") {
            // Symbol from libSystem - must be resolved from shared cache
            if let Some(addr) = cache::lookup_shared_cache_symbol(symbol_name) {
                debug!("Resolved {} from shared cache at 0x{:x}", symbol_name, addr);
                return Ok(addr);
            }
            // Not found in shared cache - this is an error
            return Err(BindingError::UnresolvedSymbol(format!(
                "{} (from {})",
                symbol_name, lib
            )));
        }

    // 4. Unknown symbol - error (no dlsym fallback)
    Err(BindingError::UnresolvedSymbol(symbol_name.to_string()))
}

/// Symbol binding at load time.
///
/// The segment_slide parameter adjusts segment addresses for dlopen'd libraries.
/// For main executable, segment_slide=0. For dlopen'd libraries, it's non-zero.
pub(crate) fn bind_symbols(macho: &MachO, segment_slide: i64) -> Result<(), BindingError> {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.fixups.is_empty() {
        trace!("No symbol fixups found, skipping symbol binding");
        return Ok(());
    }

    debug!("Binding {} symbols at load time", dyld_info.fixups.len());

    // Track the range of addresses we patch for cache flushing
    let mut min_addr: Option<u64> = None;
    let mut max_addr: Option<u64> = None;

    for fixup in &dyld_info.fixups {
        // Look up segment by index to compute absolute address
        let segment = macho.segments.get(fixup.segment_index as usize);
        let entry_addr = match segment {
            Some(seg) => (seg.vmaddr as i64 + segment_slide) as u64 + fixup.segment_offset,
            None => {
                warn!(
                    "Invalid segment index {} for symbol {}",
                    fixup.segment_index, fixup.symbol_name
                );
                continue;
            }
        };

        // Get the dylib name for this symbol (lib_ordinal is 1-based, 0 means self)
        let dylib_name = if fixup.lib_ordinal == 0 {
            None // Self reference
        } else {
            dyld_info
                .dylibs
                .get((fixup.lib_ordinal - 1) as usize)
                .map(|d| d.name.as_str())
        };

        match resolve_symbol(&fixup.symbol_name, dylib_name) {
            Ok(symbol_addr) => {
                debug!(
                    "Binding {} -> 0x{:016x} at segment[{}]+0x{:x} (0x{:016x})",
                    fixup.symbol_name,
                    symbol_addr,
                    fixup.segment_index,
                    fixup.segment_offset,
                    entry_addr
                );

                // Patch entry with resolved address
                unsafe {
                    *(entry_addr as *mut u64) = symbol_addr;
                }

                // Track range for cache flush
                min_addr = Some(min_addr.map_or(entry_addr, |m| m.min(entry_addr)));
                max_addr = Some(max_addr.map_or(entry_addr + 8, |m| m.max(entry_addr + 8)));
            }
            Err(BindingError::UnresolvedSymbol(_)) => {
                // Error out immediately on unresolved symbols
                error!("FATAL: Unresolved symbol: {}", fixup.symbol_name);
                return Err(BindingError::UnresolvedSymbol(fixup.symbol_name.clone()));
            }
            Err(e) => return Err(e),
        }
    }

    // Flush instruction cache for the patched range
    if let (Some(min), Some(max)) = (min_addr, max_addr) {
        let size = (max - min) as usize;
        crate::runtime::flush_icache_range(min as *const u8, size);
        debug!(
            "Flushed icache for binding region: 0x{:016x} ({} bytes)",
            min, size
        );
    }

    Ok(())
}
