//! Dyld Bind/Rebase Opcode Parsing
//!
//! This module handles parsing of LC_DYLD_INFO_ONLY bind and rebase opcodes,
//! which encode symbol binding and pointer rebase information in a compact
//! opcode-based format (the "compressed" format in Apple's terminology).

use super::exports;
use super::ChainedFixup;
use tracing::{debug, trace, warn};

/// A pointer rebase entry from LC_DYLD_INFO_ONLY rebase opcodes.
#[derive(Debug, Clone)]
pub struct RebaseEntry {
    pub segment_index: u8,
    pub segment_offset: u64,
}

/// Parse dyld rebase info opcodes from LC_DYLD_INFO_ONLY.
///
/// Rebase opcodes encode locations of pointers that need to be adjusted
/// by the slide amount when the image is loaded at a different address
/// than its preferred load address.
pub fn parse_dyld_rebase_info(data: &[u8]) -> Result<Vec<RebaseEntry>, String> {
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

/// Parse dyld bind info opcodes from LC_DYLD_INFO_ONLY.
///
/// Bind opcodes encode symbol references that need to be resolved at load time.
/// Each binding specifies a symbol name, library ordinal, and location to patch.
pub fn parse_dyld_bind_info(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
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
            0x50 => {
                // BIND_OPCODE_SET_TYPE_IMM
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
                        symbol_name,
                        segment_index,
                        segment_offset
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

/// Parse dyld lazy bind info opcodes from LC_DYLD_INFO_ONLY.
///
/// Lazy binding has each symbol as an independent entry, separated by BIND_OPCODE_DONE.
/// Unlike eager binding, each symbol's opcodes are self-contained.
pub fn parse_dyld_lazy_bind_info(data: &[u8]) -> Result<Vec<ChainedFixup>, String> {
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
                            symbol_name,
                            segment_index,
                            segment_offset
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
