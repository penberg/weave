//! Chained Fixups Parsing and Application
//!
//! This module handles LC_DYLD_CHAINED_FIXUPS, the newer pointer fixup format
//! used on arm64e and recent macOS versions. Unlike the opcode-based "compressed"
//! format (LC_DYLD_INFO_ONLY), chained fixups encode pointers inline with
//! next-pointer deltas forming a chain through each page.

use super::macho::*;
use super::{ChainedFixup, MachO, Segment, MACHO_BASE_ADDRESS};
use tracing::{debug, trace, warn};

/// Parse chained fixups imports from LC_DYLD_CHAINED_FIXUPS data.
///
/// This extracts symbol binding information from the chained fixups header.
/// The actual pointer chain walking is done by `apply_chained_rebases`.
pub fn parse_chained_fixups(data: &[u8], segments: &[Segment]) -> Result<Vec<ChainedFixup>, String> {
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

/// Apply chained fixup rebases (for LC_DYLD_CHAINED_FIXUPS format).
///
/// This walks the pointer chains in __DATA segments and fixes up rebase pointers.
/// Each page contains a linked list of pointers, where each pointer encodes
/// both its target value and the delta to the next pointer in the chain.
///
/// The segment_slide parameter adjusts segment addresses for dlopen'd libraries.
pub fn apply_chained_rebases(macho: &MachO, segment_slide: i64) {
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
                data.as_ptr().add(seg_starts_pos) as *const dyld_chained_starts_in_segment,
            )
        };

        let pointer_format = seg_starts.pointer_format;
        let page_size = seg_starts.page_size as u64;
        let page_count = seg_starts.page_count as usize;

        // Get the segment's base address (apply slide for dlopen'd libraries)
        let segment = match macho.segments.get(seg_idx) {
            Some(seg) => seg,
            None => continue,
        };
        let seg_base = (segment.vmaddr as i64 + segment_slide) as u64;

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
                page_idx,
                page_start,
                page_base,
                ptr_addr
            );

            // Walk the chain
            loop {
                let ptr_value = unsafe { std::ptr::read(ptr_addr as *const u64) };
                trace!(
                    "    Chain entry at 0x{:x}: raw_value=0x{:x}",
                    ptr_addr,
                    ptr_value
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
                    is_bind,
                    target,
                    next_delta
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
                        ptr_addr,
                        target,
                        new_value
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
