/// Dynamic linker for Linux ELF binaries (ld-linux.so)
///
/// This module provides symbol resolution for dynamically linked binaries
/// by using the host's libc via dlopen/dlsym, while allowing deterministic
/// replacements via the weave_symbol mechanism.
use crate::sys::linux::elf::ElfFile;
use crate::{Error, Result};
use goblin::elf::Elf;
use std::collections::HashMap;
use tracing::debug;

pub struct DynamicLinker {
    /// Symbol table: symbol name -> address
    symbols: HashMap<String, u64>,
    /// Handles for dlsym lookups (libc, libm, etc.)
    lib_handles: Vec<*mut libc::c_void>,
}

impl DynamicLinker {
    pub fn new() -> Self {
        let mut lib_handles = Vec::new();

        // Open common libraries with RTLD_NOW | RTLD_GLOBAL
        let libs = ["libc.so.6", "libm.so.6", "libpthread.so.0"];
        for lib in &libs {
            let lib_path = std::ffi::CString::new(*lib).unwrap();
            let handle = unsafe {
                libc::dlopen(lib_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL)
            };
            if !handle.is_null() {
                debug!("Opened {} for symbol resolution", lib);
                lib_handles.push(handle);
            }
        }

        // Always add RTLD_DEFAULT as fallback
        lib_handles.push(libc::RTLD_DEFAULT);

        let mut linker = Self {
            symbols: HashMap::new(),
            lib_handles,
        };
        // Register supervisor-level symbols
        linker.register_supervisor_symbols();
        linker
    }

    /// Register symbols that must be handled by the supervisor, not guest libc.
    fn register_supervisor_symbols(&mut self) {
        use crate::sys::linux::glibc;

        // __libc_start_main is critical - it sets up the C runtime
        self.symbols.insert(
            "__libc_start_main".to_string(),
            glibc::libc_start_main as u64,
        );

        // Profiling stub
        self.symbols.insert(
            "__gmon_start__".to_string(),
            glibc::gmon_start as u64,
        );

        // Transactional memory stubs (weak symbols)
        self.symbols.insert(
            "_ITM_deregisterTMCloneTable".to_string(),
            glibc::itm_stub as u64,
        );
        self.symbols.insert(
            "_ITM_registerTMCloneTable".to_string(),
            glibc::itm_stub as u64,
        );

        // C++ runtime stub
        self.symbols.insert(
            "__cxa_finalize".to_string(),
            glibc::cxa_finalize as u64,
        );
    }

    /// Load an executable and resolve its dependencies
    pub fn load_executable(&mut self, _executable: &ElfFile) -> Result<()> {
        // Using host libc, no need to load libraries ourselves
        Ok(())
    }

    /// Get the text bounds of loaded libraries
    /// For host libc approach, we don't have guest library text bounds
    pub fn get_library_text_bounds(&self) -> (u64, u64) {
        (u64::MAX, 0) // No guest library bounds
    }

    /// Resolve a symbol by name
    fn resolve_symbol(&self, name: &str) -> Option<u64> {
        // 1. Check supervisor symbols first
        if let Some(&addr) = self.symbols.get(name) {
            return Some(addr);
        }

        // 2. Check weave_symbol registry for deterministic replacements
        // These are registered with a leading underscore
        if let Some(addr) = crate::symbols::lookup(&format!("_{}", name)) {
            debug!("Resolved {} via weave_symbol to 0x{:x}", name, addr);
            return Some(addr);
        }

        // 3. Fall back to dlsym from host libraries
        let c_name = std::ffi::CString::new(name).ok()?;
        for &handle in &self.lib_handles {
            let addr = unsafe {
                libc::dlsym(handle, c_name.as_ptr())
            };
            if !addr.is_null() {
                debug!("Resolved {} via dlsym to 0x{:x}", name, addr as u64);
                return Some(addr as u64);
            }
        }

        None
    }

    /// Perform relocations for the executable
    pub fn relocate(&mut self, executable: &ElfFile) -> Result<()> {
        let elf = Elf::parse(executable.file.data).map_err(crate::ObjectFormatError::from)?;

        debug!("Processing {} .rela.dyn relocations", elf.dynrelas.len());
        debug!("Processing {} .rela.plt relocations", elf.pltrelocs.len());

        let all_relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter());

        for reloc in all_relocs {
            match reloc.r_type {
                goblin::elf::reloc::R_X86_64_RELATIVE => {
                    let reloc_addr =
                        (reloc.r_offset + crate::sys::linux::elf::ELF_BASE_ADDRESS) as *mut u64;
                    let value = crate::sys::linux::elf::ELF_BASE_ADDRESS
                        + reloc.r_addend.unwrap_or(0) as u64;
                    unsafe {
                        *reloc_addr = value;
                    }
                }
                goblin::elf::reloc::R_X86_64_GLOB_DAT | goblin::elf::reloc::R_X86_64_JUMP_SLOT => {
                    let sym_idx = reloc.r_sym;
                    if let Some(sym) = elf.dynsyms.get(sym_idx) {
                        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                            let sym_addr = self.resolve_symbol(sym_name).ok_or_else(|| {
                                Error::DynamicLinker(format!(
                                    "Unresolved symbol: {}",
                                    sym_name
                                ))
                            })?;

                            let reloc_addr = (reloc.r_offset
                                + crate::sys::linux::elf::ELF_BASE_ADDRESS)
                                as *mut u64;

                            debug!("Relocating {} to 0x{:x}", sym_name, sym_addr);
                            unsafe {
                                *reloc_addr = sym_addr;
                            }
                        }
                    }
                }
                _ => {
                    debug!("Unsupported relocation type: {}", reloc.r_type);
                }
            }
        }

        Ok(())
    }
}
