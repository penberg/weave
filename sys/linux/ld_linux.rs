/// Dynamic linker for Linux ELF binaries (ld-linux.so)
///
/// This module implements a dynamic linker similar to ld-linux.so that:
/// - Loads shared libraries
/// - Resolves symbols
/// - Performs relocations
/// - Sets up the runtime environment
use crate::sys::linux::elf::ElfFile;
use crate::{Error, Result};
use goblin::elf::Elf;
use std::collections::HashMap;
use tracing::debug;

/// Default set of libraries allowed to be loaded from the system.
/// These are known to be deterministic (no I/O, no randomness).
/// Users can extend this list with --allow-ld flags.
const DEFAULT_ALLOWED_LIBRARIES: &[&str] = &[
    "libgcc_s.so.1", // GCC runtime support (exception handling, stack unwinding)
    "libm.so.6",     // Math library (trig, exp, log, etc.)
];

pub struct DynamicLinker {
    /// Loaded shared libraries mapped by their soname
    libraries: HashMap<String, ElfFile>,
    /// Allowed libraries that are loaded from the system (tracked by dlopen handles)
    allowed_libs: HashMap<String, *mut libc::c_void>,
    /// Symbol table: symbol name -> (library name, address)
    symbols: HashMap<String, u64>,
}

impl DynamicLinker {
    pub fn new() -> Self {
        Self {
            libraries: HashMap::new(),
            allowed_libs: HashMap::new(),
            symbols: HashMap::new(),
        }
    }

    /// Load an executable and all its dependencies
    pub fn load_executable(&mut self, executable: &ElfFile) -> Result<()> {
        // Parse the dynamic section to find required libraries
        let elf = Elf::parse(executable.file.data).map_err(crate::ObjectFormatError::from)?;

        // Find PT_DYNAMIC segment
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_DYNAMIC {
                debug!("Found DYNAMIC segment at offset 0x{:x}", ph.p_offset);
                // Parse dynamic entries
                if let Some(dynamic) = &elf.dynamic {
                    for entry in &dynamic.dyns {
                        match entry.d_tag {
                            goblin::elf::dynamic::DT_NEEDED => {
                                if let Some(lib_name) = elf.dynstrtab.get_at(entry.d_val as usize) {
                                    debug!("Loading required library: {}", lib_name);
                                    self.load_library(lib_name)?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Build symbol table from all loaded libraries
        self.build_symbol_table()?;

        Ok(())
    }

    /// Build a symbol table from all loaded libraries
    fn build_symbol_table(&mut self) -> Result<()> {
        for (lib_name, lib_elf) in &self.libraries {
            let elf = Elf::parse(lib_elf.file.data).map_err(crate::ObjectFormatError::from)?;

            // Add all exported symbols from this library
            for sym in &elf.dynsyms {
                if sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        let addr = sym.st_value + crate::sys::linux::elf::ELF_BASE_ADDRESS;
                        debug!("Adding symbol {} from {} at 0x{:x}", name, lib_name, addr);
                        self.symbols.insert(name.to_string(), addr);
                    }
                }
            }
        }

        Ok(())
    }

    /// Load a shared library
    fn load_library(&mut self, name: &str) -> Result<()> {
        // Check if already loaded
        if self.libraries.contains_key(name) || self.allowed_libs.contains_key(name) {
            return Ok(()); // Already loaded
        }

        debug!("Loading shared library: {}", name);

        // Intercept libc.so.6 and provide our own implementation
        // We need to intercept this to replace non-deterministic functions like rand(), time(), etc.
        if name == "libc.so.6" {
            debug!("Intercepting libc.so.6 - providing built-in implementations");
            self.register_builtin_libc_symbols();
            return Ok(());
        }

        // Check if this library is in the default allowed list
        if DEFAULT_ALLOWED_LIBRARIES.contains(&name) {
            debug!(
                "Library {} is in the default allowed list - loading via dlopen",
                name
            );
            unsafe {
                let c_name = std::ffi::CString::new(name).unwrap();
                let handle = libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if handle.is_null() {
                    let error = std::ffi::CStr::from_ptr(libc::dlerror());
                    return Err(Error::DynamicLinker(format!(
                        "Failed to load {}: {}",
                        name,
                        error.to_string_lossy()
                    )));
                }
                debug!(
                    "Successfully loaded {} via dlopen, handle: {:?}",
                    name, handle
                );
                self.allowed_libs.insert(name.to_string(), handle);
            }
            return Ok(());
        }

        // Library not supported
        Err(Error::DynamicLinker(format!(
            "Library {} not supported (built-in: libc.so.6, allowed: {})",
            name,
            DEFAULT_ALLOWED_LIBRARIES.join(", ")
        )))
    }

    /// Register built-in libc symbol implementations
    fn register_builtin_libc_symbols(&mut self) {
        use crate::sys::linux::glibc;

        // Register __libc_start_main implementation
        self.symbols.insert(
            "__libc_start_main".to_string(),
            glibc::libc_start_main as u64,
        );

        self.symbols
            .insert("__gmon_start__".to_string(), glibc::gmon_start as u64);

        // Register transactional memory symbols (weak symbols, can be stubs)
        self.symbols.insert(
            "_ITM_deregisterTMCloneTable".to_string(),
            glibc::itm_stub as u64,
        );
        self.symbols.insert(
            "_ITM_registerTMCloneTable".to_string(),
            glibc::itm_stub as u64,
        );

        // Register C++ runtime symbols (can be stubs for C programs)
        self.symbols
            .insert("__cxa_finalize".to_string(), glibc::cxa_finalize as u64);

        // Register libc I/O functions - use the real system libc functions
        // Our weave binary is linked against libc, so we can use these directly
        self.symbols
            .insert("puts".to_string(), libc::puts as *const () as u64);
        self.symbols
            .insert("printf".to_string(), libc::printf as *const () as u64);

        // Register deterministic replacements for non-deterministic functions
        self.symbols.insert(
            "rand".to_string(),
            crate::libc::rand::weave_rand as *const () as u64,
        );
        self.symbols.insert(
            "srand".to_string(),
            crate::libc::rand::weave_srand as *const () as u64,
        );
        self.symbols.insert(
            "time".to_string(),
            crate::libc::time::weave_time as *const () as u64,
        );

        debug!("Registered built-in libc symbols");
    }

    /// Perform relocations for the executable
    pub fn relocate(&mut self, executable: &ElfFile) -> Result<()> {
        let elf = Elf::parse(executable.file.data).map_err(crate::ObjectFormatError::from)?;

        // Process both .rela.dyn and .rela.plt relocations
        debug!("Processing {} .rela.dyn relocations", elf.dynrelas.len());
        debug!("Processing {} .rela.plt relocations", elf.pltrelocs.len());

        // Combine both relocation tables
        let all_relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter());

        for reloc in all_relocs {
            debug!(
                "Processing relocation at offset 0x{:x}, type {}",
                reloc.r_offset, reloc.r_type
            );

            match reloc.r_type {
                goblin::elf::reloc::R_X86_64_RELATIVE => {
                    // R_X86_64_RELATIVE: B + A (Base address + Addend)
                    // This is used for position-independent code (PIE)
                    let reloc_addr =
                        (reloc.r_offset + crate::sys::linux::elf::ELF_BASE_ADDRESS) as *mut u64;
                    let value = crate::sys::linux::elf::ELF_BASE_ADDRESS
                        + reloc.r_addend.unwrap_or(0) as u64;

                    debug!(
                        "R_X86_64_RELATIVE: Writing 0x{:x} to relocation location 0x{:x}",
                        value, reloc_addr as u64
                    );

                    unsafe {
                        *reloc_addr = value;
                    }
                }
                goblin::elf::reloc::R_X86_64_GLOB_DAT | goblin::elf::reloc::R_X86_64_JUMP_SLOT => {
                    // Resolve the symbol
                    let sym_idx = reloc.r_sym;
                    if let Some(sym) = elf.dynsyms.get(sym_idx) {
                        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                            debug!("Resolving symbol: {}", sym_name);

                            // Try to resolve from our built-in symbol table first
                            let sym_addr = if let Some(&addr) = self.symbols.get(sym_name) {
                                addr
                            } else {
                                // If not in our table, try dlsym on allowed library handles
                                debug!(
                                    "Symbol {} not in built-in table, trying dlsym on allowed libraries",
                                    sym_name
                                );
                                let mut found_addr: Option<u64> = None;
                                unsafe {
                                    let c_name = std::ffi::CString::new(sym_name).unwrap();
                                    // Try each loaded library handle
                                    for (lib_name, handle) in &self.allowed_libs {
                                        let addr = libc::dlsym(*handle, c_name.as_ptr());
                                        if !addr.is_null() {
                                            debug!(
                                                "Resolved {} via dlsym in {} to 0x{:x}",
                                                sym_name, lib_name, addr as u64
                                            );
                                            found_addr = Some(addr as u64);
                                            break;
                                        }
                                    }
                                }
                                if let Some(addr) = found_addr {
                                    addr
                                } else {
                                    return Err(Error::DynamicLinker(format!(
                                        "Unresolved symbol: {}",
                                        sym_name
                                    )));
                                }
                            };

                            // Calculate the relocation address (with base address offset)
                            let reloc_addr = (reloc.r_offset
                                + crate::sys::linux::elf::ELF_BASE_ADDRESS)
                                as *mut u64;

                            debug!(
                                "Writing symbol {} address 0x{:x} to relocation location 0x{:x}",
                                sym_name, sym_addr, reloc_addr as u64
                            );

                            // Write the symbol address to the relocation location
                            unsafe {
                                *reloc_addr = sym_addr;
                                // Verify the write
                                let verify = *reloc_addr;
                                debug!("Verified: GOT[0x{:x}] = 0x{:x}", reloc_addr as u64, verify);
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
