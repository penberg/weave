//! Dynamic Loading API Implementation
//!
//! This module implements dlopen/dlsym/dlclose/dlerror for guest code.
//! When guest code calls dlopen(), we load the library into guest address
//! space and prepare it for binary translation.

use super::exports;
use super::{chained, tlv, MachO, MACHO_BASE_ADDRESS};
use crate::mmap::MappedFile;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, warn};

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
pub fn dlopen(path: *const libc::c_char, _flags: libc::c_int) -> *mut libc::c_void {
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

    // Calculate slide: segments have MACHO_BASE_ADDRESS baked in, but we want base_address
    let preferred_base = macho
        .segments
        .iter()
        .filter(|s| s.segname != "__PAGEZERO")
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(MACHO_BASE_ADDRESS);
    let slide = base_address as i64 - preferred_base as i64;

    // Load and link the library using the same functions as load_machfile
    super::load_segments(&macho, slide);
    super::apply_rebases(&macho, slide);
    chained::apply_chained_rebases(&macho, slide);
    if let Err(e) = super::bind_symbols(&macho, slide) {
        warn!(
            "weave_dlopen: failed to bind symbols for {}: {}",
            path_str, e
        );
        // Continue anyway - some symbols might still work
    }
    tlv::initialize_tlv_descriptors(&macho, slide);

    // Extract exported symbols from the library
    let exports = extract_exports(&macho, slide);

    // Find text segment for translation tracking
    let (text_start, text_end) = find_text_range(&macho, slide);

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
pub fn dlsym(handle: *mut libc::c_void, symbol: *const libc::c_char) -> *mut libc::c_void {
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
/// This handles libraries loaded via dlopen.
pub fn dlclose(handle: *mut libc::c_void) -> libc::c_int {
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
pub fn dlerror() -> *mut libc::c_char {
    // TODO: Track and return actual error messages
    std::ptr::null_mut()
}

/// Extract exported symbols from a Mach-O library by parsing the exports trie
fn extract_exports(macho: &MachO, slide: i64) -> HashMap<String, u64> {
    let dyld_info = macho.parse_dyld_info();

    if dyld_info.exports_trie.is_empty() {
        debug!("No exports trie found");
        return HashMap::new();
    }

    // Symbol offsets in the trie are relative to the preferred load address.
    // Apply slide to get the actual address.
    let preferred_base = macho
        .segments
        .iter()
        .filter(|s| s.segname != "__PAGEZERO")
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(MACHO_BASE_ADDRESS);
    let actual_base = (preferred_base as i64 + slide) as u64;

    // Note: We ignore re-exports here as they're only needed for shared cache resolution.
    let (exports, _re_exports) = exports::parse_exports_trie(&dyld_info.exports_trie, actual_base);

    debug!("Extracted {} exports from trie", exports.len());
    for (name, addr) in &exports {
        debug!("  Export: {} -> 0x{:x}", name, addr);
    }

    exports
}

/// Find the text segment range for a library
fn find_text_range(macho: &MachO, slide: i64) -> (u64, u64) {
    for segment in &macho.segments {
        if segment.segname == "__TEXT" {
            let start = (segment.vmaddr as i64 + slide) as u64;
            let end = start + segment.vmsize;
            return (start, end);
        }
    }
    (0, 0)
}
