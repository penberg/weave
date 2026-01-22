//! Dynamic Loading API Implementation
//!
//! This module implements dlopen/dlsym/dlclose/dlerror for guest code.
//! When guest code calls dlopen(), we load the library into guest address
//! space and prepare it for binary translation.

use super::exports;
use super::MachO;
use crate::mmap::MappedFile;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, error, warn};

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
    if let Err(e) = super::bind_symbols_at_base(&macho, base_address) {
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
        && let Some(lib) = loaded.libraries.get(&handle_addr)
    {
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
        && loaded.libraries.remove(&handle_addr).is_some()
    {
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
