//! Exports Trie Parsing
//!
//! This module provides shared functionality for parsing Mach-O exports tries,
//! used by both the dynamic loader and the shared cache symbol resolver.

use std::collections::HashMap;
use tracing::{debug, warn};

// Export symbol flags from Apple's MachOTrie.hpp
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// A re-exported symbol that needs to be resolved from another library.
#[derive(Debug, Clone)]
pub struct ReExport {
    /// The name of the exported symbol
    pub symbol_name: String,
    /// The name of the target symbol to resolve (may be the same as symbol_name)
    pub target_name: String,
}

/// Parse the exports trie and return resolved symbols and re-exports.
///
/// # Arguments
/// * `trie` - The raw trie data bytes
/// * `base_address` - Base address added to symbol offsets for final addresses
///
/// # Returns
/// A tuple of (direct_exports, re_exports) where:
/// - `direct_exports` maps symbol names to their resolved addresses
/// - `re_exports` contains symbols that need resolution from other libraries
pub fn parse_exports_trie(
    trie: &[u8],
    base_address: u64,
) -> (HashMap<String, u64>, Vec<ReExport>) {
    let mut exports = HashMap::new();
    let mut re_exports = Vec::new();

    if trie.is_empty() {
        return (exports, re_exports);
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
                    re_exports.push(ReExport {
                        symbol_name: current_symbol.clone(),
                        target_name: imported_name,
                    });
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

    (exports, re_exports)
}

/// Read a ULEB128 encoded unsigned integer, returns (value, bytes_consumed)
pub fn read_uleb128(data: &[u8], start_index: usize) -> Result<(u64, usize), &'static str> {
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