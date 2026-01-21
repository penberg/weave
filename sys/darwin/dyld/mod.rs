use crate::mmap::MappedFile;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Mutex;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

pub mod cache;
pub mod exports;
pub mod macho;

use macho::*;

// Thread-local variable (TLV) support
// TLV section type flags from mach-o/loader.h
const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
const SECTION_TYPE_MASK: u32 = 0x000000ff;

/// TLV descriptor structure (matches dyld's layout)
#[repr(C)]
pub struct TlvDescriptor {
    thunk: u64,  // Function pointer to call
    key: u64,    // pthread_key_t
    offset: u64, // Offset into TLV template
}

/// Information about TLV template for allocation
struct TlvImageInfo {
    key: libc::pthread_key_t,
    /// Start address of initialized TLV data (__thread_data)
    template_data_start: u64,
    /// Size of initialized TLV data (__thread_data)
    template_data_size: usize,
    /// Total size of TLV storage (__thread_data + __thread_bss)
    template_total_size: usize,
}

/// Global TLV image info (for single main image - could extend for multiple images)
static TLV_IMAGE_INFO: Mutex<Option<TlvImageInfo>> = Mutex::new(None);

/// Registry of dynamically loaded libraries
static LOADED_LIBRARIES: Mutex<Option<LoadedLibraries>> = Mutex::new(None);

/// Next available base address for loading libraries
/// Libraries are loaded starting at 0x400000000 to avoid overlapping with the main executable.
/// The main executable typically loads at 0x300000000 (MACHO_BASE_ADDRESS + typical vmaddr).
static NEXT_LIBRARY_BASE: Mutex<u64> = Mutex::new(0x0000000400000000);

/// Tracks all dynamically loaded libraries
struct LoadedLibraries {
    /// Map from handle (base address) to library info
    libraries: HashMap<u64, LoadedLibrary>,
}

/// Information about a loaded dynamic library
struct LoadedLibrary {
    /// Path to the library
    path: String,
    /// Exported symbols: name -> address
    exports: HashMap<String, u64>,
}

/// Main entry point for dynamic loading - parses Mach-O and sets up dyld structures
/// Returns the MachO and a set of host function addresses that were bound
pub fn load_machfile(file: MappedFile) -> Result<MachO, crate::ObjectFormatError> {
    let macho = MachO::open(file)?;
    let host_arch = crate::probe_host_arch();
    if macho.arch != host_arch {
        panic!(
            "cannot run binary for {} architecture on {} host",
            macho.arch, host_arch
        );
    }
    load_segments(&macho);
    apply_rebases(&macho);
    apply_chained_rebases(&macho);
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
    // Initialize TLV (Thread Local Variable) descriptors
    initialize_tlv_descriptors(&macho);
    Ok(macho)
}

/// Load a dynamic library for execution under Weave.
///
/// This is called when guest code calls dlopen(). Unlike native dlopen,
/// this loads the library into guest address space and prepares it for
/// binary translation.
///
/// Returns a handle (the library's base address) or null on failure.
pub fn dlopen_impl(path: *const libc::c_char, _flags: libc::c_int) -> *mut libc::c_void {
    if path.is_null() {
        return std::ptr::null_mut();
    }

    debug!("weave_dlopen: path ptr = {:p}", path);

    let path_str = match unsafe { std::ffi::CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            warn!("weave_dlopen: invalid path string");
            return std::ptr::null_mut();
        }
    };

    debug!("weave_dlopen: loading {}", path_str);

    // Open and parse the library file
    debug!("weave_dlopen: about to open file");
    let file = match MappedFile::open(path_str) {
        Ok(f) => {
            debug!("weave_dlopen: opened file successfully");
            f
        }
        Err(e) => {
            warn!("weave_dlopen: failed to open {}: {}", path_str, e);
            return std::ptr::null_mut();
        }
    };

    debug!("weave_dlopen: about to parse Mach-O");
    let macho = match MachO::open(file) {
        Ok(m) => m,
        Err(e) => {
            warn!("weave_dlopen: failed to parse {}: {}", path_str, e);
            return std::ptr::null_mut();
        }
    };

    // Allocate a new base address for this library
    let base_address = {
        let mut next_base = NEXT_LIBRARY_BASE.lock().unwrap();
        let base = *next_base;
        *next_base += 0x100000000; // 4GB spacing between libraries
        base
    };

    debug!(
        "weave_dlopen: loading {} at base 0x{:x}",
        path_str, base_address
    );

    // Load segments at the new base address
    load_segments_at_base(&macho, base_address);

    // Bind symbols for this library (using the actual base address)
    if let Err(e) = bind_symbols_at_base(&macho, base_address) {
        warn!(
            "weave_dlopen: failed to bind symbols for {}: {}",
            path_str, e
        );
        // Continue anyway - some symbols might still work
    }

    // Extract exported symbols from the library
    let exports = extract_exports(&macho, base_address);

    // Find text segment for translation tracking
    let (text_start, text_end) = find_text_range(&macho, base_address);

    // Register the library
    {
        let mut libs = LOADED_LIBRARIES.lock().unwrap();
        if libs.is_none() {
            *libs = Some(LoadedLibraries {
                libraries: HashMap::new(),
            });
        }
        if let Some(ref mut loaded) = *libs {
            loaded.libraries.insert(
                base_address,
                LoadedLibrary {
                    path: path_str.to_string(),
                    exports,
                },
            );
        }
    }

    debug!(
        "weave_dlopen: loaded {} at 0x{:x}, text range 0x{:x}-0x{:x}",
        path_str, base_address, text_start, text_end
    );

    // Expand the execution context's text bounds to include this library
    // This allows the dispatcher to translate code in dynamically loaded libraries
    if text_end > 0 {
        let ctx = crate::runtime::get_current_context();
        // If library's text_end is beyond current bounds, extend them
        if text_end > ctx.text_end {
            debug!(
                "Extending text_end from 0x{:x} to 0x{:x} for library",
                ctx.text_end, text_end
            );
            ctx.text_end = text_end;
        }
        // If library's text_start is before current start, extend it
        if text_start < ctx.text_start {
            debug!(
                "Extending text_start from 0x{:x} to 0x{:x} for library",
                ctx.text_start, text_start
            );
            ctx.text_start = text_start;
        }
    }

    base_address as *mut libc::c_void
}

/// Look up a symbol in a dynamically loaded library.
pub fn dlsym_impl(handle: *mut libc::c_void, symbol: *const libc::c_char) -> *mut libc::c_void {
    if symbol.is_null() {
        return std::ptr::null_mut();
    }

    let symbol_str = match unsafe { std::ffi::CStr::from_ptr(symbol) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    debug!(
        "weave_dlsym: looking up '{}' in handle {:p}",
        symbol_str, handle
    );

    // Check if this is a symbol we intercept for determinism
    // dlsym uses names without underscore prefix, so prepend it for lookup
    let mangled_name = format!("_{}", symbol_str);
    if let Some(addr) = crate::symbols::lookup(&mangled_name) {
        return addr as *mut libc::c_void;
    }

    let handle_addr = handle as u64;

    // Look up in our loaded libraries
    let libs = LOADED_LIBRARIES.lock().unwrap();
    if let Some(ref loaded) = *libs
        && let Some(lib) = loaded.libraries.get(&handle_addr) {
            // Try exact match first
            if let Some(&addr) = lib.exports.get(symbol_str) {
                debug!(
                    "weave_dlsym: {} -> 0x{:x} (from {})",
                    symbol_str, addr, lib.path
                );
                return addr as *mut libc::c_void;
            }

            // On macOS, C symbols have a leading underscore in the binary
            // Try with underscore prefix
            let mangled = format!("_{}", symbol_str);
            if let Some(&addr) = lib.exports.get(&mangled) {
                debug!(
                    "weave_dlsym: {} (as {}) -> 0x{:x} (from {})",
                    symbol_str, mangled, addr, lib.path
                );
                return addr as *mut libc::c_void;
            }

            debug!(
                "weave_dlsym: {} not found in {} exports",
                symbol_str, lib.path
            );
        }

    // Fall back to platform dlsym for system libraries
    debug!(
        "weave_dlsym: {} not found in Weave libraries, trying platform",
        symbol_str
    );
    unsafe { libc::dlsym(handle, symbol) }
}

/// Close a dynamically loaded library.
///
/// This handles libraries loaded via dlopen_impl.
pub fn dlclose_impl(handle: *mut libc::c_void) -> libc::c_int {
    let handle_addr = handle as u64;

    debug!("weave_dlclose: closing handle {:p}", handle);

    // Check if this is a Weave-loaded library
    let mut libs = LOADED_LIBRARIES.lock().unwrap();
    if let Some(ref mut loaded) = *libs
        && loaded.libraries.remove(&handle_addr).is_some() {
            debug!(
                "weave_dlclose: successfully closed Weave library at 0x{:x}",
                handle_addr
            );
            // Note: We don't actually unmap the memory since other code might still reference it
            // This is a simplification - a full implementation would track references
            return 0;
        }

    // Not a Weave library, pass to platform dlclose
    debug!("weave_dlclose: not a Weave library, passing to platform");
    unsafe { libc::dlclose(handle) }
}

/// Return error message for last dlopen/dlsym/dlclose error.
///
/// For now, we just return NULL (no error) since we don't track errors.
pub fn dlerror_impl() -> *mut libc::c_char {
    // TODO: Track and return actual error messages
    std::ptr::null_mut()
}

/// Load segments at a specific base address (for dynamic libraries)
fn load_segments_at_base(macho: &MachO, base_address: u64) {
    let fd = macho.file.fd;

    // Calculate the slide (difference between requested base and library's preferred base)
    let preferred_base = macho
        .segments
        .iter()
        .filter(|s| s.segname != "__PAGEZERO")
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(0);
    let slide = base_address.wrapping_sub(preferred_base);

    for segment in &macho.segments {
        // Skip __PAGEZERO - it's a guard region
        if segment.segname == "__PAGEZERO" {
            continue;
        }

        let target_addr = segment.vmaddr.wrapping_add(slide);
        debug!(
            "Loading segment {} at 0x{:016x} (vmsize={} filesize={}) prot={:x}",
            segment.segname, target_addr, segment.vmsize, segment.filesize, segment.prot
        );

        let prot = segment.prot & !libc::PROT_EXEC;

        // Handle zerofill (BSS): when vmsize > filesize, the extra bytes must be zeroed.
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
                    "Failed to map anonymous memory for segment at 0x{:x}: {}",
                    target_addr,
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
                        "Failed to map file data for segment at 0x{:x}: {}",
                        target_addr,
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
                error!(
                    "Failed to map segment at 0x{:x}: {}",
                    target_addr,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Extract exported symbols from a Mach-O library by parsing the exports trie
fn extract_exports(macho: &MachO, base_address: u64) -> HashMap<String, u64> {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.exports_trie.is_empty() {
        debug!("No exports trie found");
        return HashMap::new();
    }

    // Symbol offsets in the trie are relative to the original image base (0).
    // We add base_address directly to get the final address.
    // Note: We ignore re-exports here as they're only needed for shared cache resolution.
    let (exports, _re_exports) = exports::parse_exports_trie(&dyld_info.exports_trie, base_address);

    debug!("Extracted {} exports from trie", exports.len());
    for (name, addr) in &exports {
        debug!("  Export: {} -> 0x{:x}", name, addr);
    }

    exports
}

/// Find the text segment range for a library
fn find_text_range(macho: &MachO, base_address: u64) -> (u64, u64) {
    let preferred_base = macho
        .segments
        .iter()
        .filter(|s| s.segname != "__PAGEZERO")
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(0);
    let slide = base_address.wrapping_sub(preferred_base);

    for segment in &macho.segments {
        if segment.segname == "__TEXT" {
            let start = segment.vmaddr.wrapping_add(slide);
            let end = start + segment.vmsize;
            return (start, end);
        }
    }
    (0, 0)
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
const MACHO_BASE_ADDRESS: u64 = 0x0000000200000000;

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
pub struct RebaseEntry {
    pub segment_index: u8,
    pub segment_offset: u64,
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

fn load_segments(macho: &MachO) {
    let fd = macho.file.fd;
    for segment in &macho.segments {
        debug!(
            "Loading segment {} at 0x{:016x} (vmsize={} filesize={}) prot={:x}",
            segment.segname, segment.vmaddr, segment.vmsize, segment.filesize, segment.prot
        );

        // Skip __PAGEZERO - it's a guard region that shouldn't be mapped
        if segment.segname == "__PAGEZERO" {
            continue;
        }

        let prot = segment.prot & !libc::PROT_EXEC;

        // Handle zerofill (BSS): when vmsize > filesize, the extra bytes must be zeroed.
        // We handle this by:
        // 1. First mapping the entire vmsize as anonymous memory (zeroed)
        // 2. Then mapping the file data over the first filesize bytes
        if segment.vmsize > segment.filesize {
            // Map zeroed anonymous memory for the entire segment
            let anon_data = unsafe {
                libc::mmap(
                    segment.vmaddr as *mut libc::c_void,
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
                        segment.vmaddr as *mut libc::c_void,
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
                    segment.vmaddr as *mut libc::c_void,
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

/// Apply rebase fixups to adjust internal pointers for relocation
fn apply_rebases(macho: &MachO) {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.rebases.is_empty() {
        return;
    }

    debug!("Applying {} rebase fixups", dyld_info.rebases.len());

    // The slide is the difference between where we loaded and where the binary expected to be
    // Segments are stored with MACHO_BASE_ADDRESS already added, so slide is 0
    // But internal pointers in the file don't have MACHO_BASE_ADDRESS, so we add it
    let slide = MACHO_BASE_ADDRESS;

    for rebase in &dyld_info.rebases {
        let segment = match macho.segments.get(rebase.segment_index as usize) {
            Some(seg) => seg,
            None => {
                warn!("Invalid segment index {} for rebase", rebase.segment_index);
                continue;
            }
        };

        let entry_addr = segment.vmaddr + rebase.segment_offset;

        // Read the current pointer value, add the slide, and write it back
        unsafe {
            let ptr = entry_addr as *mut u64;
            let old_value = *ptr;
            let new_value = old_value.wrapping_add(slide);
            *ptr = new_value;
            trace!(
                "Rebase at 0x{:x}: 0x{:x} -> 0x{:x}",
                entry_addr, old_value, new_value
            );
        }
    }

    debug!(
        "Applied {} rebase fixups with slide 0x{:x}",
        dyld_info.rebases.len(),
        slide
    );
}

/// Apply chained fixup rebases (for LC_DYLD_CHAINED_FIXUPS format)
/// This walks the pointer chains in __DATA segments and fixes up rebase pointers.
fn apply_chained_rebases(macho: &MachO) {
    let dyld_info = macho.parse_dyld_info();
    let data = &dyld_info.chained_fixups_data;

    if data.is_empty() {
        return;
    }

    if data.len() < std::mem::size_of::<dyld_chained_fixups_header>() {
        warn!("Chained fixups data too small for header");
        return;
    }

    let header = unsafe { std::ptr::read(data.as_ptr() as *const dyld_chained_fixups_header) };

    if header.starts_offset == 0 {
        debug!("No chained starts in fixups");
        return;
    }

    // Parse the starts_in_image structure
    let starts_offset = header.starts_offset as usize;
    if starts_offset + 4 > data.len() {
        warn!("Chained starts offset out of bounds");
        return;
    }

    let starts_in_image = unsafe {
        std::ptr::read(data.as_ptr().add(starts_offset) as *const dyld_chained_starts_in_image)
    };

    debug!("Chained starts: seg_count={}", starts_in_image.seg_count);

    // For DYLD_CHAINED_PTR_64_OFFSET, targets are offsets from mach_header.
    // We need to add the __TEXT segment's load address (where mach_header is).
    // For other formats, targets are vmaddrs that need the standard slide.
    let slide = MACHO_BASE_ADDRESS;
    let text_base = macho
        .segments
        .iter()
        .find(|s| s.segname == "__TEXT")
        .map(|s| s.vmaddr)
        .unwrap_or(MACHO_BASE_ADDRESS);
    let mut total_rebases = 0u64;

    // Process each segment
    for seg_idx in 0..starts_in_image.seg_count as usize {
        // Read the offset to this segment's starts structure
        let seg_info_offset_pos = starts_offset + 4 + seg_idx * 4;
        if seg_info_offset_pos + 4 > data.len() {
            continue;
        }
        let seg_info_offset =
            unsafe { std::ptr::read(data.as_ptr().add(seg_info_offset_pos) as *const u32) };

        if seg_info_offset == 0 {
            // No fixups for this segment
            continue;
        }

        let seg_starts_pos = starts_offset + seg_info_offset as usize;
        if seg_starts_pos + std::mem::size_of::<dyld_chained_starts_in_segment>() > data.len() {
            continue;
        }

        let seg_starts = unsafe {
            std::ptr::read(
                data.as_ptr().add(seg_starts_pos) as *const dyld_chained_starts_in_segment
            )
        };

        let pointer_format = seg_starts.pointer_format;
        let page_size = seg_starts.page_size as u64;
        let page_count = seg_starts.page_count as usize;

        // Get the segment's base address
        let segment = match macho.segments.get(seg_idx) {
            Some(seg) => seg,
            None => continue,
        };
        let seg_base = segment.vmaddr;

        trace!(
            "Segment {} ({}): format={}, page_size={}, page_count={}, base=0x{:x}, segment_offset=0x{:x}",
            seg_idx,
            segment.segname,
            pointer_format,
            page_size,
            page_count,
            seg_base,
            seg_starts.segment_offset
        );

        // Read page_start array
        let page_starts_pos = seg_starts_pos + 22; // offset to page_start array in struct
        for page_idx in 0..page_count {
            let page_start_pos = page_starts_pos + page_idx * 2;
            if page_start_pos + 2 > data.len() {
                break;
            }
            let page_start =
                unsafe { std::ptr::read(data.as_ptr().add(page_start_pos) as *const u16) };

            // DYLD_CHAINED_PTR_START_NONE means no fixups on this page
            if page_start == 0xFFFF {
                continue;
            }

            // Calculate the address of the first pointer in this chain
            let page_base = seg_base + (page_idx as u64 * page_size);
            let mut ptr_addr = page_base + page_start as u64;

            trace!(
                "  Page {}: page_start=0x{:x}, page_base=0x{:x}, chain_start=0x{:x}",
                page_idx, page_start, page_base, ptr_addr
            );

            // Walk the chain
            loop {
                let ptr_value = unsafe { std::ptr::read(ptr_addr as *const u64) };
                trace!(
                    "    Chain entry at 0x{:x}: raw_value=0x{:x}",
                    ptr_addr, ptr_value
                );

                // Decode based on pointer format
                // Stride is 8 bytes for ARM64E formats, 4 bytes for 64-bit formats
                let stride: u64 = match pointer_format {
                    DYLD_CHAINED_PTR_ARM64E
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => 8,
                    DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => 4,
                    _ => 4,
                };

                let (is_bind, target, next_delta) = match pointer_format {
                    DYLD_CHAINED_PTR_ARM64E
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND
                    | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
                        // ARM64E format:
                        // bit 63: auth (1 = authenticated pointer)
                        // bit 62: bind (1 = bind, 0 = rebase)
                        // bits 51-61: next (11 bits)
                        let is_auth = (ptr_value >> 63) & 1 != 0;
                        let is_bind = (ptr_value >> 62) & 1 != 0;
                        let next = ((ptr_value >> 51) & 0x7FF) as u16;

                        if is_bind {
                            (true, 0, next)
                        } else if is_auth {
                            // Authenticated rebase: target is in low 32 bits (actual vmaddr)
                            // For auth pointers, the target IS the virtual address, not an offset
                            let target = ptr_value & 0xFFFFFFFF;
                            (false, target, next)
                        } else {
                            // Non-authenticated rebase
                            let target = if pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
                                // 24-bit target (low bits only)
                                ptr_value & 0x00FFFFFF
                            } else if pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND {
                                // 34-bit target (low 34 bits)
                                ptr_value & 0x3FFFFFFFF
                            } else {
                                // DYLD_CHAINED_PTR_ARM64E: 43-bit target
                                ptr_value & 0x7FFFFFFFFFF
                            };
                            // High8 is in bits 43-50 for non-auth pointers
                            let high8 = ((ptr_value >> 43) & 0xFF) << 56;
                            (false, target | high8, next)
                        }
                    }
                    DYLD_CHAINED_PTR_64 => {
                        // DYLD_CHAINED_PTR_64: bind bit is bit 63
                        // target: bits 0-50 (51 bits)
                        // high8: bits 51-58 (8 bits)
                        // next: bits 59-62 (4 bits)
                        let is_bind = (ptr_value >> 63) & 1 != 0;
                        let next = ((ptr_value >> 59) & 0xF) as u16; // 4 bits
                        if is_bind {
                            (true, 0, next)
                        } else {
                            // Rebase: target is in low 51 bits
                            let target = ptr_value & 0x7FFFFFFFFFFFF;
                            let high8 = ((ptr_value >> 51) & 0xFF) << 56;
                            (false, target | high8, next)
                        }
                    }
                    DYLD_CHAINED_PTR_64_OFFSET => {
                        // DYLD_CHAINED_PTR_64_OFFSET: target is offset from mach_header
                        // target: bits 0-35 (36 bits)
                        // high8: bits 36-43 (8 bits)
                        // reserved: bits 44-50 (7 bits)
                        // next: bits 51-62 (12 bits)
                        // bind: bit 63 (1 bit)
                        let is_bind = (ptr_value >> 63) & 1 != 0;
                        let next = ((ptr_value >> 51) & 0xFFF) as u16; // 12 bits
                        if is_bind {
                            (true, 0, next)
                        } else {
                            // Rebase: target is offset in low 36 bits
                            let target = ptr_value & 0xFFFFFFFFF; // 36 bits
                            let high8 = ((ptr_value >> 36) & 0xFF) << 56;
                            (false, target | high8, next)
                        }
                    }
                    _ => {
                        trace!("Unknown pointer format: {}", pointer_format);
                        break;
                    }
                };

                trace!(
                    "      is_bind={}, target=0x{:x}, next_delta={}",
                    is_bind, target, next_delta
                );

                if !is_bind && target != 0 {
                    // This is a rebase - apply the appropriate base address
                    // DYLD_CHAINED_PTR_64_OFFSET: target is offset from mach_header, add text_base
                    // Other formats: target is vmaddr, add standard slide
                    let effective_slide = if pointer_format == DYLD_CHAINED_PTR_64_OFFSET {
                        text_base
                    } else {
                        slide
                    };
                    let new_value = target.wrapping_add(effective_slide);
                    unsafe {
                        std::ptr::write(ptr_addr as *mut u64, new_value);
                    }
                    trace!(
                        "Chained rebase at 0x{:x}: 0x{:x} -> 0x{:x}",
                        ptr_addr, target, new_value
                    );
                    total_rebases += 1;
                }

                // Follow the chain
                if next_delta == 0 {
                    break;
                }
                ptr_addr += next_delta as u64 * stride;
            }
        }
    }

    debug!(
        "Applied {} chained rebases with slide 0x{:x}",
        total_rebases, slide
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
                    if let Ok(parsed_rebases) = parse_dyld_rebase_info(rebase_data) {
                        dyld_info.rebases.extend(parsed_rebases);
                    } else {
                        warn!("Failed to parse dyld rebase info");
                    }
                }

                // Parse the binding information (eager binding)
                if dyld_info_cmd.bind_off > 0 && dyld_info_cmd.bind_size > 0 {
                    let bind_data = &file.data[dyld_info_cmd.bind_off as usize
                        ..(dyld_info_cmd.bind_off + dyld_info_cmd.bind_size) as usize];
                    if let Ok(parsed_fixups) = parse_dyld_bind_info(bind_data) {
                        dyld_info.fixups.extend(parsed_fixups);
                    } else {
                        warn!("Failed to parse dyld bind info");
                    }
                }

                // Parse the lazy binding information (resolve lazily-bound symbols eagerly)
                if dyld_info_cmd.lazy_bind_off > 0 && dyld_info_cmd.lazy_bind_size > 0 {
                    let lazy_bind_data = &file.data[dyld_info_cmd.lazy_bind_off as usize
                        ..(dyld_info_cmd.lazy_bind_off + dyld_info_cmd.lazy_bind_size) as usize];
                    if let Ok(parsed_fixups) = parse_dyld_lazy_bind_info(lazy_bind_data) {
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

                if let Ok(parsed_fixups) = parse_chained_fixups(fixups_data, &segments) {
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

fn parse_chained_fixups(data: &[u8], segments: &[Segment]) -> Result<Vec<ChainedFixup>, String> {
    if data.len() < std::mem::size_of::<dyld_chained_fixups_header>() {
        return Err("Chained fixups data too small".to_string());
    }

    let header = unsafe { std::ptr::read(data.as_ptr() as *const dyld_chained_fixups_header) };

    debug!(
        "Chained fixups header: version={}, imports_count={}, imports_offset={}, symbols_offset={}",
        header.fixups_version, header.imports_count, header.imports_offset, header.symbols_offset
    );

    // Find the __DATA_CONST segment index dynamically
    // Main executables have: __PAGEZERO(0), __TEXT(1), __DATA_CONST(2), __LINKEDIT(3)
    // Dylibs have: __TEXT(0), __DATA_CONST(1), __LINKEDIT(2)
    let data_const_index = segments
        .iter()
        .position(|s| s.segname == "__DATA_CONST")
        .unwrap_or(2) as u8;

    debug!("Using segment index {} for __DATA_CONST", data_const_index);

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
                    segment_index: data_const_index,
                    segment_offset: i as u64 * 8,
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

/// pthread destructor for TLV storage
unsafe extern "C" fn tlv_free(storage: *mut libc::c_void) {
    if !storage.is_null() {
        unsafe { libc::free(storage) };
    }
}

/// Allocate and initialize TLV storage for the current thread.
/// Called when a TLV is accessed for the first time on this thread.
unsafe fn tlv_allocate_and_initialize_for_key(key: libc::pthread_key_t) -> *mut u8 {
    let info = TLV_IMAGE_INFO.lock().unwrap();
    if let Some(ref tlv_info) = *info {
        if tlv_info.key != key {
            // Key mismatch - shouldn't happen
            return std::ptr::null_mut();
        }

        // Allocate buffer for this thread's TLV storage (total size including bss)
        // Use calloc to zero-initialize, then copy the initialized template data
        let buffer = unsafe { libc::calloc(1, tlv_info.template_total_size) as *mut u8 };
        if buffer.is_null() {
            return std::ptr::null_mut();
        }

        // Copy initialized values from __thread_data (the rest is already zero from calloc)
        if tlv_info.template_data_size > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    tlv_info.template_data_start as *const u8,
                    buffer,
                    tlv_info.template_data_size,
                );
            }
        }

        // Set this thread's value for the key
        unsafe { libc::pthread_setspecific(key, buffer as *mut libc::c_void) };

        debug!(
            "Allocated TLV storage for thread: {:p} ({} bytes, {} initialized)",
            buffer, tlv_info.template_total_size, tlv_info.template_data_size
        );
        buffer
    } else {
        std::ptr::null_mut()
    }
}

// Assembly wrapper that preserves caller-saved registers like native _tlv_bootstrap
unsafe extern "C" {
    /// TLV access wrapper that preserves all caller-saved registers.
    /// This is necessary because macOS's native _tlv_bootstrap preserves
    /// registers beyond what the standard ABI requires.
    pub fn weave_tlv_get_addr_wrapper(descriptor: *mut TlvDescriptor) -> *mut u8;
}

/// TLV get_addr implementation for arm64.
/// Called by the assembly wrapper when guest code accesses a thread-local variable.
/// x0 = pointer to TlvDescriptor
/// Returns: address of the TLV
///
/// NOTE: This function is called via weave_tlv_get_addr_wrapper which preserves
/// caller-saved registers. Do not call this directly from TLV descriptors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn weave_tlv_get_addr_impl(descriptor: *mut TlvDescriptor) -> *mut u8 {
    // Read all descriptor fields for debugging
    let thunk = unsafe { (*descriptor).thunk };
    let key = unsafe { (*descriptor).key as libc::pthread_key_t };
    let offset = unsafe { (*descriptor).offset as usize };

    trace!(
        "TLV thunk called: descriptor={:p}, thunk=0x{:x}, key={}, offset=0x{:x}",
        descriptor, thunk, key, offset
    );

    // Get this thread's TLV storage
    let mut base = unsafe { libc::pthread_getspecific(key) as *mut u8 };

    if base.is_null() {
        // First access on this thread - allocate and initialize
        base = unsafe { tlv_allocate_and_initialize_for_key(key) };
        if base.is_null() {
            panic!("Failed to allocate TLV storage");
        }
    }

    // Return address of the specific TLV
    let result = unsafe { base.add(offset) };

    // Debug: log what value is at this TLV address
    let value_at_tlv = unsafe { *(result as *const u64) };
    trace!(
        "TLV access: descriptor={:p}, key={}, offset=0x{:x}, base={:p}, result={:p}, value=0x{:x}",
        descriptor, key, offset, base, result, value_at_tlv
    );

    result
}

/// Initialize TLV descriptors for the loaded Mach-O.
/// This replaces the thunk and key fields in all TLV descriptors.
pub fn initialize_tlv_descriptors(macho: &MachO) {
    // Find TLV-related sections
    let mut thread_vars_addr = None;
    let mut thread_vars_size = 0u64;
    let mut template_data_start = None;
    let mut template_data_size = 0usize;
    let mut template_total_size = 0usize;

    for section in &macho.sections {
        let flags = get_section_flags(macho, &section.sectname, &section.segname);
        let section_type = flags & SECTION_TYPE_MASK;

        match section_type {
            S_THREAD_LOCAL_VARIABLES => {
                // __thread_vars section - contains TLV descriptors
                thread_vars_addr = Some(section.addr);
                thread_vars_size = section.size;
                debug!(
                    "Found __thread_vars at 0x{:x}, size {}",
                    section.addr, section.size
                );
            }
            S_THREAD_LOCAL_REGULAR => {
                // __thread_data - initialized TLV template
                if template_data_start.is_none() {
                    template_data_start = Some(section.addr);
                }
                template_data_size += section.size as usize;
                template_total_size += section.size as usize;
                debug!(
                    "Found __thread_data at 0x{:x}, size {} (initialized)",
                    section.addr, section.size
                );
            }
            S_THREAD_LOCAL_ZEROFILL => {
                // __thread_bss - zero-initialized TLV template
                if template_data_start.is_none() {
                    template_data_start = Some(section.addr);
                }
                template_total_size += section.size as usize;
                debug!(
                    "Found __thread_bss at 0x{:x}, size {} (zero-fill)",
                    section.addr, section.size
                );
            }
            _ => {}
        }
    }

    // If no TLV sections found, nothing to do
    let thread_vars_addr = match thread_vars_addr {
        Some(addr) => addr,
        None => return,
    };

    let template_data_start = match template_data_start {
        Some(addr) => addr,
        None => {
            warn!("TLV descriptors found but no template sections");
            return;
        }
    };

    debug!(
        "Initializing TLV: descriptors at 0x{:x}, template at 0x{:x} ({} bytes data, {} bytes total)",
        thread_vars_addr, template_data_start, template_data_size, template_total_size
    );

    // Create a pthread key for this image's TLVs
    let mut key: libc::pthread_key_t = 0;
    let result = unsafe { libc::pthread_key_create(&mut key, Some(tlv_free)) };
    if result != 0 {
        error!("Failed to create pthread key for TLV: {}", result);
        return;
    }

    debug!("Created pthread key {} for TLV", key);

    // Store the TLV info for later use
    {
        let mut info = TLV_IMAGE_INFO.lock().unwrap();
        *info = Some(TlvImageInfo {
            key,
            template_data_start,
            template_data_size,
            template_total_size,
        });
    }

    // Patch all TLV descriptors
    let num_descriptors = thread_vars_size as usize / std::mem::size_of::<TlvDescriptor>();
    let descriptors = thread_vars_addr as *mut TlvDescriptor;

    for i in 0..num_descriptors {
        unsafe {
            let desc = descriptors.add(i);
            // Replace thunk with our implementation (via assembly wrapper that preserves registers)
            (*desc).thunk = weave_tlv_get_addr_wrapper as u64;
            // Set the key
            (*desc).key = key as u64;
            // offset remains unchanged - it's already correct
            trace!(
                "Patched TLV descriptor {}: thunk=0x{:x}, key={}, offset={}",
                i,
                (*desc).thunk,
                (*desc).key,
                (*desc).offset
            );
        }
    }

    debug!("Initialized {} TLV descriptors", num_descriptors);
}

/// Get section flags from the Mach-O file
fn get_section_flags(macho: &MachO, sectname: &str, segname: &str) -> u32 {
    // We need to parse section flags from the file
    // For now, use naming convention as a fallback
    if sectname == "__thread_vars" {
        return S_THREAD_LOCAL_VARIABLES;
    }
    if sectname == "__thread_data" {
        return S_THREAD_LOCAL_REGULAR;
    }
    if sectname == "__thread_bss" {
        return S_THREAD_LOCAL_ZEROFILL;
    }

    // Parse from the file to get actual flags
    let file = &macho.file;
    let header_size = std::mem::size_of::<mach_header_64>();
    let mut offset = header_size;

    let header = unsafe { std::ptr::read(file.data.as_ptr() as *const mach_header_64) };

    for _ in 0..header.ncmds {
        if offset >= file.data.len() {
            break;
        }
        let cmd = unsafe { std::ptr::read(file.data.as_ptr().add(offset) as *const load_command) };

        if cmd.cmd == LC_SEGMENT_64 {
            let segment = unsafe {
                std::ptr::read(file.data.as_ptr().add(offset) as *const segment_command_64)
            };

            let seg_name = String::from_utf8_lossy(&segment.segname)
                .trim_end_matches('\0')
                .to_string();

            if seg_name == segname {
                let sections_offset = offset + std::mem::size_of::<segment_command_64>();
                for i in 0..segment.nsects {
                    let section_offset =
                        sections_offset + i as usize * std::mem::size_of::<section_64>();
                    if section_offset + std::mem::size_of::<section_64>() > file.data.len() {
                        break;
                    }
                    let section = unsafe {
                        std::ptr::read(file.data.as_ptr().add(section_offset) as *const section_64)
                    };

                    let sect_name = String::from_utf8_lossy(&section.sectname)
                        .trim_end_matches('\0')
                        .to_string();

                    if sect_name == sectname {
                        return section.flags;
                    }
                }
            }
        }

        offset += cmd.cmdsize as usize;
    }

    0
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
        "__tlv_bootstrap" => return Ok(weave_tlv_get_addr_wrapper as *const () as u64),
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

// Use exports::read_uleb128 for ULEB128 decoding

/// Parse dyld rebase info opcodes from LC_DYLD_INFO_ONLY
fn parse_dyld_rebase_info(data: &[u8]) -> Result<Vec<RebaseEntry>, String> {
    let mut rebases = Vec::new();
    let mut i = 0;

    let mut segment_index = 0u8;
    let mut segment_offset = 0u64;

    while i < data.len() {
        let opcode = data[i];
        let immediate = opcode & 0x0F;
        let command = opcode & 0xF0;

        match command {
            0x00 => {
                // REBASE_OPCODE_DONE
                break;
            }
            0x10 => {
                // REBASE_OPCODE_SET_TYPE_IMM
                // We ignore the type - all rebases are pointer adjustments
            }
            0x20 => {
                // REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                segment_index = immediate;
                match exports::read_uleb128(data, i + 1) {
                    Ok((offset, bytes_consumed)) => {
                        segment_offset = offset;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 segment offset".to_string()),
                }
            }
            0x30 => {
                // REBASE_OPCODE_ADD_ADDR_ULEB
                match exports::read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset = segment_offset.wrapping_add(addr_add);
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 address add".to_string()),
                }
            }
            0x40 => {
                // REBASE_OPCODE_ADD_ADDR_IMM_SCALED
                segment_offset = segment_offset.wrapping_add((immediate as u64) * 8);
            }
            0x50 => {
                // REBASE_OPCODE_DO_REBASE_IMM_TIMES
                let count = immediate as usize;
                for _ in 0..count {
                    rebases.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                    });
                    segment_offset = segment_offset.wrapping_add(8);
                }
            }
            0x60 => {
                // REBASE_OPCODE_DO_REBASE_ULEB_TIMES
                match exports::read_uleb128(data, i + 1) {
                    Ok((count, bytes_consumed)) => {
                        for _ in 0..count {
                            rebases.push(RebaseEntry {
                                segment_index,
                                segment_offset,
                            });
                            segment_offset = segment_offset.wrapping_add(8);
                        }
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 count".to_string()),
                }
            }
            0x70 => {
                // REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
                rebases.push(RebaseEntry {
                    segment_index,
                    segment_offset,
                });
                match exports::read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset = segment_offset.wrapping_add(addr_add).wrapping_add(8);
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 address add".to_string()),
                }
            }
            0x80 => {
                // REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                let (count, count_bytes) = match exports::read_uleb128(data, i + 1) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 count".to_string()),
                };
                let (skip, skip_bytes) = match exports::read_uleb128(data, i + 1 + count_bytes) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 skip".to_string()),
                };

                for _ in 0..count {
                    rebases.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                    });
                    segment_offset = segment_offset.wrapping_add(skip).wrapping_add(8);
                }
                i += count_bytes + skip_bytes;
            }
            _ => {
                // Unknown opcode - skip
            }
        }
        i += 1;
    }

    debug!("Parsed {} rebase entries", rebases.len());
    Ok(rebases)
}

/// Parse dyld bind info opcodes from LC_DYLD_INFO_ONLY
fn parse_dyld_bind_info(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
    let mut fixups = Vec::new();
    let mut i = 0;

    let mut lib_ordinal = 0u8;
    let mut symbol_name = String::new();
    let mut segment_index = 0u8;
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
                match exports::read_uleb128(data, i + 1) {
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
                segment_index = immediate;
                match exports::read_uleb128(data, i + 1) {
                    Ok((offset, bytes_consumed)) => {
                        segment_offset = offset;
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 segment offset".to_string()),
                }
            }
            0x80 => {
                // BIND_OPCODE_ADD_ADDR_ULEB
                // Note: Large unsigned values effectively subtract (wrapping semantics)
                match exports::read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset = segment_offset.wrapping_add(addr_add);
                        i += bytes_consumed;
                    }
                    Err(_) => return Err("Failed to read ULEB128 address add".to_string()),
                }
            }
            0x90 => {
                // BIND_OPCODE_DO_BIND
                // Create a fixup entry - lib_ordinal validation happens during symbol binding
                if !symbol_name.is_empty() {
                    trace!(
                        "Creating fixup for symbol: {} (segment={}, offset=0x{:x})",
                        symbol_name, segment_index, segment_offset
                    );
                    fixups.push(ChainedFixup {
                        symbol_name: symbol_name.clone(),
                        lib_ordinal: lib_ordinal as u32,
                        segment_index,
                        segment_offset,
                    });
                }
                segment_offset = segment_offset.wrapping_add(8); // Advance to next pointer slot
            }
            0xA0 => {
                // BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
                // Bind and advance by specified amount
                if !symbol_name.is_empty() {
                    fixups.push(ChainedFixup {
                        symbol_name: symbol_name.clone(),
                        lib_ordinal: lib_ordinal as u32,
                        segment_index,
                        segment_offset,
                    });
                }
                match exports::read_uleb128(data, i + 1) {
                    Ok((addr_add, bytes_consumed)) => {
                        segment_offset = segment_offset.wrapping_add(addr_add);
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
                        segment_index,
                        segment_offset,
                    });
                }
                segment_offset = segment_offset.wrapping_add((immediate as u64) * 8);
            }
            0xC0 => {
                // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                // Bind multiple times with skip
                let (count, count_bytes) = match exports::read_uleb128(data, i + 1) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 count".to_string()),
                };
                let (skip, skip_bytes) = match exports::read_uleb128(data, i + 1 + count_bytes) {
                    Ok(result) => result,
                    Err(_) => return Err("Failed to read ULEB128 skip".to_string()),
                };

                for _ in 0..count {
                    if !symbol_name.is_empty() {
                        fixups.push(ChainedFixup {
                            symbol_name: symbol_name.clone(),
                            lib_ordinal: lib_ordinal as u32,
                            segment_index,
                            segment_offset,
                        });
                    }
                    // Advance by skip + pointer_size (8 bytes)
                    segment_offset = segment_offset.wrapping_add(skip).wrapping_add(8);
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

/// Parse dyld lazy bind info opcodes from LC_DYLD_INFO_ONLY
/// Lazy binding has each symbol as an independent entry, separated by BIND_OPCODE_DONE
fn parse_dyld_lazy_bind_info(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
    let mut fixups = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let mut lib_ordinal = 0u8;
        let mut symbol_name = String::new();
        let mut segment_index = 0u8;
        let mut segment_offset = 0u64;

        // Parse opcodes for one symbol until BIND_OPCODE_DONE
        while i < data.len() {
            let opcode = data[i];
            let immediate = opcode & 0x0F;
            let command = opcode & 0xF0;

            match command {
                0x00 => {
                    // BIND_OPCODE_DONE - end of this symbol's binding
                    i += 1;
                    break;
                }
                0x10 => {
                    // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                    lib_ordinal = immediate;
                }
                0x20 => {
                    // BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
                    match exports::read_uleb128(data, i + 1) {
                        Ok((ordinal, bytes_consumed)) => {
                            lib_ordinal = ordinal as u8;
                            i += bytes_consumed;
                        }
                        Err(_) => return Err("Failed to read ULEB128 ordinal".to_string()),
                    }
                }
                0x30 => {
                    // BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
                    lib_ordinal = immediate;
                }
                0x40 => {
                    // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                    i += 1;
                    let start = i;
                    while i < data.len() && data[i] != 0 {
                        i += 1;
                    }
                    if i < data.len() {
                        symbol_name = String::from_utf8_lossy(&data[start..i]).to_string();
                    }
                }
                0x50 => {
                    // BIND_OPCODE_SET_TYPE_IMM - ignore
                }
                0x60 => {
                    // BIND_OPCODE_SET_ADDEND_SLEB
                    if let Ok((_, bytes_consumed)) = exports::read_uleb128(data, i + 1) {
                        i += bytes_consumed;
                    }
                }
                0x70 => {
                    // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                    segment_index = immediate;
                    match exports::read_uleb128(data, i + 1) {
                        Ok((offset, bytes_consumed)) => {
                            segment_offset = offset;
                            i += bytes_consumed;
                        }
                        Err(_) => return Err("Failed to read ULEB128 segment offset".to_string()),
                    }
                }
                0x90 => {
                    // BIND_OPCODE_DO_BIND
                    if !symbol_name.is_empty() {
                        trace!(
                            "Creating lazy fixup for symbol: {} (segment={}, offset=0x{:x})",
                            symbol_name, segment_index, segment_offset
                        );
                        fixups.push(ChainedFixup {
                            symbol_name: symbol_name.clone(),
                            lib_ordinal: lib_ordinal as u32,
                            segment_index,
                            segment_offset,
                        });
                    }
                }
                _ => {
                    // Skip unknown opcodes
                }
            }
            i += 1;
        }
    }
    Ok(fixups)
}

/// Symbol binding at load time (like real dyld)
/// Returns a set of host function addresses that were bound
pub fn bind_symbols(macho: &MachO) -> Result<(), BindingError> {
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
            Some(seg) => seg.vmaddr + fixup.segment_offset,
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

/// Symbol binding for dynamically loaded libraries.
/// Takes the actual base address where the library is loaded.
fn bind_symbols_at_base(macho: &MachO, base_address: u64) -> Result<(), BindingError> {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.fixups.is_empty() {
        trace!("No symbol fixups found, skipping symbol binding");
        return Ok(());
    }

    // Calculate slide: segments have MACHO_BASE_ADDRESS baked in, but library is at base_address
    // We need to find the preferred base from segment vmaddrs
    let preferred_base = macho
        .segments
        .iter()
        .filter(|s| s.segname != "__PAGEZERO")
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(MACHO_BASE_ADDRESS);
    let slide = base_address.wrapping_sub(preferred_base);

    debug!(
        "Binding {} symbols at load time (slide=0x{:x})",
        dyld_info.fixups.len(),
        slide
    );

    let mut min_addr: Option<u64> = None;
    let mut max_addr: Option<u64> = None;

    for fixup in &dyld_info.fixups {
        // Look up segment by index and apply slide
        let segment = macho.segments.get(fixup.segment_index as usize);
        let entry_addr = match segment {
            Some(seg) => seg.vmaddr.wrapping_add(slide) + fixup.segment_offset,
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
                    "Binding {} -> 0x{:016x} at 0x{:x}",
                    fixup.symbol_name, symbol_addr, entry_addr
                );

                unsafe {
                    *(entry_addr as *mut u64) = symbol_addr;
                }

                min_addr = Some(min_addr.map_or(entry_addr, |m| m.min(entry_addr)));
                max_addr = Some(max_addr.map_or(entry_addr + 8, |m| m.max(entry_addr + 8)));
            }
            Err(BindingError::UnresolvedSymbol(_)) => {
                error!("FATAL: Unresolved symbol: {}", fixup.symbol_name);
                return Err(BindingError::UnresolvedSymbol(fixup.symbol_name.clone()));
            }
            Err(e) => return Err(e),
        }
    }

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
