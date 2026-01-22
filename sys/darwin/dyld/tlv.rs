//! Thread-Local Variable (TLV) Support
//!
//! This module handles macOS thread-local variables, which use a special
//! descriptor-based mechanism. Each TLV has a descriptor containing a thunk
//! function pointer, a pthread key, and an offset into the TLV template.
//!
//! When guest code accesses a TLV, it calls through the descriptor's thunk,
//! which we replace with our own implementation that allocates per-thread
//! storage on first access.

use super::macho::*;
use super::MachO;
use std::sync::Mutex;
use tracing::{debug, error, trace, warn};

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
        descriptor,
        thunk,
        key,
        offset
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
        descriptor,
        key,
        offset,
        base,
        result,
        value_at_tlv
    );

    result
}

/// Initialize TLV descriptors for the loaded Mach-O.
/// This replaces the thunk and key fields in all TLV descriptors.
///
/// The segment_slide parameter adjusts section addresses for dlopen'd libraries.
pub fn initialize_tlv_descriptors(macho: &MachO, segment_slide: i64) {
    // Find TLV-related sections
    let mut thread_vars_addr = None;
    let mut thread_vars_size = 0u64;
    let mut template_data_start = None;
    let mut template_data_size = 0usize;
    let mut template_total_size = 0usize;

    for section in &macho.sections {
        let flags = get_section_flags(macho, &section.sectname, &section.segname);
        let section_type = flags & SECTION_TYPE_MASK;
        let section_addr = (section.addr as i64 + segment_slide) as u64;

        match section_type {
            S_THREAD_LOCAL_VARIABLES => {
                // __thread_vars section - contains TLV descriptors
                thread_vars_addr = Some(section_addr);
                thread_vars_size = section.size;
                debug!(
                    "Found __thread_vars at 0x{:x}, size {}",
                    section_addr, section.size
                );
            }
            S_THREAD_LOCAL_REGULAR => {
                // __thread_data - initialized TLV template
                if template_data_start.is_none() {
                    template_data_start = Some(section_addr);
                }
                template_data_size += section.size as usize;
                template_total_size += section.size as usize;
                debug!(
                    "Found __thread_data at 0x{:x}, size {} (initialized)",
                    section_addr, section.size
                );
            }
            S_THREAD_LOCAL_ZEROFILL => {
                // __thread_bss - zero-initialized TLV template
                if template_data_start.is_none() {
                    template_data_start = Some(section_addr);
                }
                template_total_size += section.size as usize;
                debug!(
                    "Found __thread_bss at 0x{:x}, size {} (zero-fill)",
                    section_addr, section.size
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
