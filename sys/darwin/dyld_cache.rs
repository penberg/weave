//! dyld Shared Cache Discovery and Symbol Resolution
//!
//! On macOS 11+, system libraries like libSystem.B.dylib exist only in the
//! dyld shared cache. This module discovers symbols in the shared cache
//! and makes them available for binary translation.

use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, warn};

/// Registry for symbols resolved from the dyld shared cache.
/// Maps symbol name -> address in shared cache (already mapped, will be translated).
static SHARED_CACHE_SYMBOLS: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

// dyld APIs for discovering loaded images in the shared cache
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(image_index: u32) -> *const mach_header_64;
    fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
    fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
}

// Mach-O constants and structures (matching those in dyld.rs)
const MACHO_MAGIC: u32 = 0xfeedfacf;
const LC_REQ_DYLD: u32 = 0x80000000;
const LC_SEGMENT_64: u32 = 0x19;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;

#[repr(C)]
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
struct load_command {
    cmd: u32,
    cmdsize: u32,
}

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

#[repr(C)]
struct linkedit_data_command {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

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

/// Discover all shared cache libraries and extract their exports.
/// libSystem.B.dylib is an umbrella library that re-exports from sub-libraries
/// (libsystem_c.dylib, libsystem_m.dylib, etc.), so we need to scan all of them.
fn discover_shared_cache_symbols() -> HashMap<String, u64> {
    let count = unsafe { _dyld_image_count() };
    let mut all_exports = HashMap::new();

    debug!(
        "Discovering shared cache libraries ({} images loaded)",
        count
    );

    for i in 0..count {
        let name_ptr = unsafe { _dyld_get_image_name(i) };
        if name_ptr.is_null() {
            continue;
        }

        let name = match unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Only process system libraries in the shared cache
        // These are typically under /usr/lib/system/ or /usr/lib/
        if !name.starts_with("/usr/lib/") && !name.starts_with("/System/") {
            continue;
        }

        let header = unsafe { _dyld_get_image_header(i) };
        if header.is_null() {
            continue;
        }

        let header_addr = header as u64;
        let slide = unsafe { _dyld_get_image_vmaddr_slide(i) } as i64;

        debug!(
            "Processing shared cache library: {} at 0x{:x} (slide=0x{:x})",
            name, header_addr, slide
        );

        // Parse exports from this library
        if let Some(exports) = parse_shared_cache_exports(header_addr, slide)
            && !exports.is_empty() {
                debug!("Found {} exports in {}", exports.len(), name);
                // Add to our combined symbol table
                all_exports.extend(exports);
            }
    }

    // Resolve re-exports: __REEXPORT__<name>__FROM__<target>
    let reexport_prefix = "__REEXPORT__";
    let reexport_separator = "__FROM__";
    let reexport_keys: Vec<String> = all_exports
        .keys()
        .filter(|k| k.starts_with(reexport_prefix))
        .cloned()
        .collect();

    for key in reexport_keys {
        all_exports.remove(&key);
        // Parse: __REEXPORT__<name>__FROM__<target>
        if let Some(rest) = key.strip_prefix(reexport_prefix)
            && let Some(sep_pos) = rest.find(reexport_separator) {
                let symbol_name = &rest[..sep_pos];
                let target_name = &rest[sep_pos + reexport_separator.len()..];

                // Look up the target symbol
                if let Some(&addr) = all_exports.get(target_name) {
                    debug!(
                        "Resolved re-export {} -> {} at 0x{:x}",
                        symbol_name, target_name, addr
                    );
                    all_exports.insert(symbol_name.to_string(), addr);
                } else {
                    debug!(
                        "Re-export {} -> {} (target not found, may be in another library)",
                        symbol_name, target_name
                    );
                }
            }
    }

    debug!(
        "Total shared cache symbols discovered: {}",
        all_exports.len()
    );
    all_exports
}

/// Parse exports from an in-memory Mach-O header (for shared cache images)
fn parse_shared_cache_exports(header_addr: u64, slide: i64) -> Option<HashMap<String, u64>> {
    let mut exports = HashMap::new();

    // Read the mach_header_64 at header_addr
    let header = unsafe { std::ptr::read(header_addr as *const mach_header_64) };

    if header.magic != MACHO_MAGIC {
        warn!(
            "Invalid Mach-O magic 0x{:x} in shared cache image at 0x{:x}",
            header.magic, header_addr
        );
        return None;
    }

    // Find __LINKEDIT segment info first - we need it to compute data addresses
    let mut linkedit_vmaddr = 0u64;
    let mut linkedit_fileoff = 0u64;
    let mut exports_trie_off = 0u32;
    let mut exports_trie_size = 0u32;

    // Parse load commands
    let mut offset = header_addr + std::mem::size_of::<mach_header_64>() as u64;

    for _ in 0..header.ncmds {
        let cmd = unsafe { std::ptr::read(offset as *const load_command) };

        match cmd.cmd {
            LC_SEGMENT_64 => {
                let segment = unsafe { std::ptr::read(offset as *const segment_command_64) };
                let segname = String::from_utf8_lossy(&segment.segname)
                    .trim_end_matches('\0')
                    .to_string();

                if segname == "__LINKEDIT" {
                    linkedit_vmaddr = segment.vmaddr;
                    linkedit_fileoff = segment.fileoff;
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                let linkedit = unsafe { std::ptr::read(offset as *const linkedit_data_command) };
                exports_trie_off = linkedit.dataoff;
                exports_trie_size = linkedit.datasize;
            }
            LC_DYLD_INFO_ONLY => {
                let info = unsafe { std::ptr::read(offset as *const dyld_info_command) };
                if info.export_size > 0 {
                    exports_trie_off = info.export_off;
                    exports_trie_size = info.export_size;
                }
            }
            _ => {}
        }

        offset += cmd.cmdsize as u64;
    }

    if exports_trie_size == 0 {
        debug!("No exports trie found in shared cache image");
        return Some(exports);
    }

    // In the shared cache, data is accessed via: (linkedit_vmaddr + slide) + (dataoff - linkedit_fileoff)
    // The slide accounts for ASLR - linkedit_vmaddr is the pre-slide address from the Mach-O header
    let slid_linkedit = (linkedit_vmaddr as i64 + slide) as u64;
    let trie_addr = slid_linkedit + (exports_trie_off as u64 - linkedit_fileoff);

    debug!(
        "Exports trie at 0x{:x} (size {}), linkedit vmaddr 0x{:x}, slid to 0x{:x}, fileoff 0x{:x}, trie_off 0x{:x}",
        trie_addr,
        exports_trie_size,
        linkedit_vmaddr,
        slid_linkedit,
        linkedit_fileoff,
        exports_trie_off
    );

    let trie_data =
        unsafe { std::slice::from_raw_parts(trie_addr as *const u8, exports_trie_size as usize) };

    // Debug: dump first 32 bytes of trie data
    let preview: Vec<u8> = trie_data.iter().take(32).copied().collect();
    debug!("  Trie bytes: {:02x?}", preview);

    // Sanity check: if first byte looks like garbage (e.g., > 200 children), skip this trie
    if exports_trie_size > 0 {
        // Read what would be terminal_size
        if let Ok((terminal_size, term_bytes)) = read_uleb128(trie_data, 0) {
            let children_pos = if terminal_size > 0 {
                term_bytes + terminal_size as usize
            } else {
                term_bytes
            };
            if children_pos < trie_data.len() {
                let num_children = trie_data[children_pos];
                debug!(
                    "  Root: terminal_size={}, num_children={}",
                    terminal_size, num_children
                );
                // If num_children is unreasonably large, the data is likely corrupt
                if num_children > 100 {
                    warn!(
                        "Skipping corrupt trie: num_children={} is unreasonably large",
                        num_children
                    );
                    return Some(exports);
                }
            }
        }
    }

    // The base address for symbols is the header address (already includes slide)
    parse_exports_trie(trie_data, header_addr, &mut exports);

    Some(exports)
}

/// Read a ULEB128 encoded unsigned integer, returns (value, bytes_consumed)
fn read_uleb128(data: &[u8], start_index: usize) -> Result<(u64, usize), &'static str> {
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
            return Err("ULEB128 value too large");
        }
    }

    Err("Unexpected end of data while reading ULEB128")
}

/// Parse the exports trie and populate the exports map.
/// `base_address` is added to symbol offsets to get final addresses.
fn parse_exports_trie(trie: &[u8], base_address: u64, exports: &mut HashMap<String, u64>) {
    if trie.is_empty() {
        return;
    }

    // Start at the root node with empty prefix
    let mut stack: Vec<(usize, String)> = vec![(0, String::new())];
    let mut iterations = 0usize;
    const MAX_ITERATIONS: usize = 100_000;

    while let Some((node_offset, current_symbol)) = stack.pop() {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            warn!(
                "parse_exports_trie: exceeded {} iterations, stack size={}, aborting",
                MAX_ITERATIONS,
                stack.len()
            );
            break;
        }
        if iterations <= 20 {
            debug!(
                "  iter {}: node_offset={}, symbol={:?}, stack_size={}",
                iterations,
                node_offset,
                current_symbol,
                stack.len()
            );
        }
        if node_offset >= trie.len() {
            continue;
        }

        let mut pos = node_offset;

        // Read terminal info size
        let (terminal_size, bytes_read) = match read_uleb128(trie, pos) {
            Ok(result) => result,
            Err(_) => continue,
        };
        pos += bytes_read;

        // If this is a terminal node, extract the symbol info
        if terminal_size > 0 {
            let terminal_start = pos;

            // Read flags
            let (flags, flags_bytes) = match read_uleb128(trie, pos) {
                Ok(result) => result,
                Err(_) => continue,
            };
            pos += flags_bytes;

            // Check for re-export or stub flags
            const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
            const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

            if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 {
                // Re-exported symbol - read ordinal and imported name
                let (_, ordinal_bytes) = match read_uleb128(trie, pos) {
                    Ok(result) => result,
                    Err(_) => continue,
                };
                pos += ordinal_bytes;
                // Read imported name (null-terminated string)
                let imported_name_start = pos;
                while pos < trie.len() && trie[pos] != 0 {
                    pos += 1;
                }
                let imported_name = if pos > imported_name_start {
                    String::from_utf8_lossy(&trie[imported_name_start..pos]).to_string()
                } else {
                    // Empty imported name means use the same name as the export
                    current_symbol.clone()
                };
                // Record this re-export for later resolution
                if !current_symbol.is_empty() && !imported_name.is_empty() {
                    // Store as a marker - we'll resolve after all symbols are collected
                    // Use a special prefix to identify re-exports
                    exports.insert(
                        format!("__REEXPORT__{}__FROM__{}", current_symbol, imported_name),
                        0,
                    );
                }
            } else if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0 {
                // Stub and resolver - read stub offset and resolver offset
                let (stub_offset, stub_bytes) = match read_uleb128(trie, pos) {
                    Ok(result) => result,
                    Err(_) => continue,
                };
                pos += stub_bytes;
                let (_resolver_offset, _) = match read_uleb128(trie, pos) {
                    Ok(result) => result,
                    Err(_) => continue,
                };
                // Use stub offset as the symbol address
                let symbol_addr = stub_offset.wrapping_add(base_address);
                if !current_symbol.is_empty() {
                    exports.insert(current_symbol.clone(), symbol_addr);
                }
            } else {
                // Regular export - read symbol offset
                let (symbol_offset, _) = match read_uleb128(trie, pos) {
                    Ok(result) => result,
                    Err(_) => continue,
                };
                let symbol_addr = symbol_offset.wrapping_add(base_address);
                if !current_symbol.is_empty() {
                    exports.insert(current_symbol.clone(), symbol_addr);
                }
            }

            // Move past terminal info
            pos = terminal_start + terminal_size as usize;
        }

        if pos >= trie.len() {
            continue;
        }

        // Read number of children
        let num_children = trie[pos] as usize;
        pos += 1;
        if iterations <= 20 {
            debug!("    num_children={}", num_children);
        }

        // Sanity check: reasonable tries don't have >100 children per node
        if num_children > 100 {
            continue;
        }

        // Process each child edge
        for _ in 0..num_children {
            if pos >= trie.len() {
                break;
            }

            // Read edge label (null-terminated string)
            let label_start = pos;
            while pos < trie.len() && trie[pos] != 0 {
                pos += 1;
            }
            let label = String::from_utf8_lossy(&trie[label_start..pos]).to_string();
            pos += 1; // skip null

            // Read child node offset
            let (child_offset, offset_bytes) = match read_uleb128(trie, pos) {
                Ok(result) => result,
                Err(_) => break,
            };
            pos += offset_bytes;

            // Skip offset 0 - it would loop back to root (matches Apple's dyld behavior)
            // Also skip out-of-bounds offsets
            if child_offset == 0 || child_offset as usize >= trie.len() {
                continue;
            }

            // Push child onto stack with accumulated symbol name
            let child_symbol = format!("{}{}", current_symbol, label);
            if iterations <= 20 {
                debug!(
                    "    pushing child: offset={}, label={:?}",
                    child_offset, label
                );
            }
            stack.push((child_offset as usize, child_symbol));
        }
    }
}

/// Initialize the shared cache symbol registry.
/// Called once at startup to discover ALL shared cache exports.
pub fn init_shared_cache_symbols() {
    let mut cache = SHARED_CACHE_SYMBOLS.lock().unwrap();
    if cache.is_some() {
        return; // Already initialized
    }

    let symbols = discover_shared_cache_symbols();
    debug!("Initialized {} shared cache symbols", symbols.len());
    *cache = Some(symbols);
}

/// Look up a symbol in the shared cache registry.
/// Returns the symbol address if found, None otherwise.
/// Lazily initializes the cache on first lookup.
pub fn lookup_shared_cache_symbol(symbol_name: &str) -> Option<u64> {
    // Ensure cache is initialized
    init_shared_cache_symbols();

    let cache = SHARED_CACHE_SYMBOLS.lock().unwrap();
    if let Some(ref symbols) = *cache {
        symbols.get(symbol_name).copied()
    } else {
        None
    }
}

/// Get the text bounds of code we're using from the shared cache.
/// Returns (min_addr, max_addr) or None if no shared cache symbols are used.
pub fn get_shared_cache_text_bounds() -> Option<(u64, u64)> {
    let cache = SHARED_CACHE_SYMBOLS.lock().unwrap();
    if let Some(ref symbols) = *cache {
        if symbols.is_empty() {
            return None;
        }

        // Return the known, fixed shared cache region bounds.
        // We don't compute from symbol addresses because some symbols may have
        // corrupt addresses from damaged trie data.
        // ARM64: 0x180000000, size ~4GB
        // x86_64: 0x7FFF00000000, size ~4GB
        #[cfg(target_arch = "aarch64")]
        const SHARED_CACHE_BASE: u64 = 0x180000000;
        #[cfg(target_arch = "aarch64")]
        const SHARED_CACHE_SIZE: u64 = 0x100000000; // 4GB

        #[cfg(target_arch = "x86_64")]
        const SHARED_CACHE_BASE: u64 = 0x7FFF00000000;
        #[cfg(target_arch = "x86_64")]
        const SHARED_CACHE_SIZE: u64 = 0xFFE00000;

        let cache_start = SHARED_CACHE_BASE;
        let cache_end = SHARED_CACHE_BASE + SHARED_CACHE_SIZE;

        debug!(
            "Shared cache text bounds: 0x{:x} - 0x{:x}",
            cache_start, cache_end
        );
        Some((cache_start, cache_end))
    } else {
        None
    }
}
