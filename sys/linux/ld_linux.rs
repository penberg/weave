/// Dynamic linker for Linux ELF binaries (ld-linux.so)
///
/// This module loads guest shared objects into guest memory and resolves
/// symbols from those guest ELFs plus Weave-provided overrides.
use crate::mmap::MappedFile;
use crate::sys::linux::elf::{
    ELF_LIBRARY_ADDRESS_STRIDE, ELF_LIBRARY_BASE_ADDRESS, ElfFile, load_elf,
};
use crate::{Error, Result};
use goblin::elf::Elf;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

#[derive(Copy, Clone)]
enum RelocationLookup {
    Normal,
    Copy,
}

pub struct DynamicLinker {
    /// Symbol table: symbol name -> address
    symbols: HashMap<String, u64>,
    /// Guest-loaded shared libraries.
    libraries: Vec<LoadedLibrary>,
    /// Paths of already loaded guest libraries.
    loaded_paths: HashMap<PathBuf, usize>,
    /// Next guest base to use for a library mapping.
    next_library_base: u64,
}

pub struct LoadedLibrary {
    pub path: PathBuf,
    pub elf: ElfFile,
}

impl DynamicLinker {
    pub fn new() -> Self {
        let mut linker = Self {
            symbols: HashMap::new(),
            libraries: Vec::new(),
            loaded_paths: HashMap::new(),
            next_library_base: ELF_LIBRARY_BASE_ADDRESS,
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
            glibc::libc_start_main as *const () as u64,
        );

        // Profiling stub
        self.symbols.insert(
            "__gmon_start__".to_string(),
            glibc::gmon_start as *const () as u64,
        );

        // Transactional memory stubs (weak symbols)
        self.symbols.insert(
            "_ITM_deregisterTMCloneTable".to_string(),
            glibc::itm_stub as *const () as u64,
        );
        self.symbols.insert(
            "_ITM_registerTMCloneTable".to_string(),
            glibc::itm_stub as *const () as u64,
        );

        // C++ runtime stub
        self.symbols.insert(
            "__cxa_finalize".to_string(),
            glibc::cxa_finalize as *const () as u64,
        );
    }

    /// Load an executable and resolve its dependencies
    pub fn load_executable(&mut self, executable_path: &str, executable: &ElfFile) -> Result<()> {
        let executable_dir = Path::new(executable_path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        for lib in &executable.needed_libraries {
            self.load_library_recursive(lib, &executable_dir)?;
        }

        Ok(())
    }

    /// Get the text bounds of loaded libraries
    pub fn get_library_text_bounds(&self) -> (u64, u64) {
        let mut text_start = u64::MAX;
        let mut text_end = 0;

        for library in &self.libraries {
            for section in &library.elf.sections {
                if !section.executable {
                    continue;
                }
                text_start = text_start.min(section.addr);
                text_end = text_end.max(section.addr + section.size);
            }
        }

        (text_start, text_end)
    }

    /// Perform relocations for the executable
    pub fn relocate(&mut self, executable: &ElfFile) -> Result<()> {
        self.relocate_object(executable)?;

        for index in 0..self.libraries.len() {
            let library = &self.libraries[index];
            self.relocate_object(&library.elf)?;
        }

        Ok(())
    }

    fn relocate_object(&self, object: &ElfFile) -> Result<()> {
        let elf = Elf::parse(object.file.data).map_err(crate::ObjectFormatError::from)?;

        debug!(
            "Processing {} .rela.dyn relocations for base 0x{:x}",
            elf.dynrelas.len(),
            object.base_address
        );
        debug!(
            "Processing {} .rela.plt relocations for base 0x{:x}",
            elf.pltrelocs.len(),
            object.base_address
        );

        let all_relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter());

        for reloc in all_relocs {
            match reloc.r_type {
                goblin::elf::reloc::R_X86_64_RELATIVE => {
                    let reloc_addr = (reloc.r_offset + object.base_address) as *mut u64;
                    let value = object.base_address + reloc.r_addend.unwrap_or(0) as u64;
                    unsafe {
                        *reloc_addr = value;
                    }
                }
                goblin::elf::reloc::R_X86_64_64 => {
                    let sym_idx = reloc.r_sym;
                    let sym_addr = self.resolve_relocation_symbol(
                        &elf,
                        object,
                        sym_idx,
                        RelocationLookup::Normal,
                    )?;
                    let reloc_addr = (reloc.r_offset + object.base_address) as *mut u64;
                    let value = sym_addr.wrapping_add(reloc.r_addend.unwrap_or(0) as u64);
                    unsafe {
                        *reloc_addr = value;
                    }
                }
                goblin::elf::reloc::R_X86_64_GLOB_DAT | goblin::elf::reloc::R_X86_64_JUMP_SLOT => {
                    let sym_idx = reloc.r_sym;
                    let sym_addr = self.resolve_relocation_symbol(
                        &elf,
                        object,
                        sym_idx,
                        RelocationLookup::Normal,
                    )?;

                    let reloc_addr = (reloc.r_offset + object.base_address) as *mut u64;
                    if let Some(sym) = elf.dynsyms.get(sym_idx)
                        && let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name)
                    {
                        debug!("Relocating {} to 0x{:x}", sym_name, sym_addr);
                    }
                    unsafe {
                        *reloc_addr = sym_addr;
                    }
                }
                goblin::elf::reloc::R_X86_64_COPY => {
                    let sym_idx = reloc.r_sym;
                    if let Some(sym) = elf.dynsyms.get(sym_idx) {
                        let sym_addr = self.resolve_relocation_symbol(
                            &elf,
                            object,
                            sym_idx,
                            RelocationLookup::Copy,
                        )?;

                        let dst = (reloc.r_offset + object.base_address) as *mut u8;
                        let size = sym.st_size as usize;

                        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                            debug!(
                                "COPY relocation: {} ({} bytes from 0x{:x} to {:?})",
                                sym_name, size, sym_addr, dst
                            );
                        }
                        unsafe {
                            std::ptr::copy_nonoverlapping(sym_addr as *const u8, dst, size);
                        }
                    }
                }
                goblin::elf::reloc::R_X86_64_IRELATIVE => {
                    let reloc_addr = (reloc.r_offset + object.base_address) as *mut u64;
                    let resolver = object.base_address + reloc.r_addend.unwrap_or(0) as u64;
                    let value = self.call_ifunc_resolver(resolver);
                    unsafe {
                        *reloc_addr = value;
                    }
                }
                _ => {
                    return Err(Error::DynamicLinker(format!(
                        "Unsupported relocation type: {}",
                        reloc.r_type
                    )));
                }
            }
        }

        self.apply_relr_relocations(&elf, object);

        Ok(())
    }

    fn resolve_relocation_symbol(
        &self,
        elf: &Elf<'_>,
        object: &ElfFile,
        sym_idx: usize,
        lookup: RelocationLookup,
    ) -> Result<u64> {
        let sym = elf.dynsyms.get(sym_idx).ok_or_else(|| {
            Error::DynamicLinker(format!("Invalid symbol index in relocation: {}", sym_idx))
        })?;
        if matches!(lookup, RelocationLookup::Normal)
            && sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
            && sym.st_value != 0
        {
            return Ok(object.base_address + sym.st_value);
        }

        let sym_name = elf.dynstrtab.get_at(sym.st_name).ok_or_else(|| {
            Error::DynamicLinker(format!(
                "Missing symbol name for relocation index {}",
                sym_idx
            ))
        })?;

        self.resolve_external_symbol(sym_name, matches!(lookup, RelocationLookup::Copy), object)
            .ok_or_else(|| {
                let kind = match lookup {
                    RelocationLookup::Normal => "symbol",
                    RelocationLookup::Copy => "COPY symbol",
                };
                Error::DynamicLinker(format!("Unresolved {}: {}", kind, sym_name))
            })
    }

    fn apply_relr_relocations(&self, elf: &Elf<'_>, object: &ElfFile) {
        let relr_section = elf
            .section_headers
            .iter()
            .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".relr.dyn"));
        let Some(relr_section) = relr_section else {
            return;
        };

        let start = relr_section.sh_offset as usize;
        let end = start.saturating_add(relr_section.sh_size as usize);
        if end > object.file.data.len() {
            warn!(
                "Ignoring truncated .relr.dyn for object at base 0x{:x}",
                object.base_address
            );
            return;
        }

        let data = &object.file.data[start..end];
        let mut next_offset = 0u64;

        for chunk in data.chunks_exact(8) {
            let entry = u64::from_le_bytes(chunk.try_into().unwrap());
            if (entry & 1) == 0 {
                self.apply_relr_entry(object.base_address, entry);
                next_offset = entry + 8;
                continue;
            }

            let bitmap = entry >> 1;
            for bit in 0..63 {
                if ((bitmap >> bit) & 1) == 0 {
                    continue;
                }
                self.apply_relr_entry(object.base_address, next_offset + bit * 8);
            }
            next_offset += 63 * 8;
        }
    }

    fn apply_relr_entry(&self, base_address: u64, offset: u64) {
        let reloc_addr = (base_address + offset) as *mut u64;
        unsafe {
            *reloc_addr += base_address;
        }
    }

    fn resolve_external_symbol(
        &self,
        name: &str,
        skip_same_object: bool,
        requesting_object: &ElfFile,
    ) -> Option<u64> {
        if let Some(&addr) = self.symbols.get(name) {
            return Some(addr);
        }

        if let Some(addr) = crate::symbols::lookup(&format!("_{}", name)) {
            debug!("Resolved {} via weave_symbol to 0x{:x}", name, addr);
            return Some(addr);
        }

        for library in &self.libraries {
            if skip_same_object && library.elf.base_address == requesting_object.base_address {
                continue;
            }
            let elf = match Elf::parse(library.elf.file.data) {
                Ok(elf) => elf,
                Err(_) => continue,
            };
            for sym in &elf.dynsyms {
                if sym.st_name == 0
                    || sym.st_value == 0
                    || sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize
                {
                    continue;
                }

                let sym_name = match elf.dynstrtab.get_at(sym.st_name) {
                    Some(sym_name) => sym_name,
                    None => continue,
                };

                if sym_name == name {
                    let addr = library.elf.base_address + sym.st_value;
                    debug!(
                        "Resolved {} via guest library {} to 0x{:x}",
                        name,
                        library.path.display(),
                        addr
                    );
                    return Some(addr);
                }
            }
        }

        None
    }

    fn call_ifunc_resolver(&self, resolver: u64) -> u64 {
        let ctx = crate::runtime::get_current_context();
        crate::runtime::x86::translate_and_call(ctx, resolver)
    }

    fn load_library_recursive(&mut self, library_name: &str, requester_dir: &Path) -> Result<()> {
        let library_path = self.find_library_path(library_name, requester_dir)?;

        if self.loaded_paths.contains_key(&library_path) {
            return Ok(());
        }

        debug!("Loading guest library {}", library_path.display());
        let file = MappedFile::open(library_path.to_str().ok_or_else(|| {
            Error::DynamicLinker(format!(
                "Non-UTF-8 library path: {}",
                library_path.display()
            ))
        })?)
        .map_err(|e| {
            Error::DynamicLinker(format!("Failed to open {}: {}", library_path.display(), e))
        })?;

        let base_address = self.allocate_library_base();
        let elf = load_elf(file, base_address).map_err(|e| {
            Error::DynamicLinker(format!("Failed to load {}: {}", library_path.display(), e))
        })?;

        let library_dir = library_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        let dependencies = elf.needed_libraries.clone();

        let library_index = self.libraries.len();
        self.loaded_paths
            .insert(library_path.clone(), library_index);
        self.libraries.push(LoadedLibrary {
            path: library_path.clone(),
            elf,
        });

        for dependency in dependencies {
            self.load_library_recursive(&dependency, &library_dir)?;
        }

        Ok(())
    }

    fn allocate_library_base(&mut self) -> u64 {
        let base_address = self.next_library_base;
        self.next_library_base += ELF_LIBRARY_ADDRESS_STRIDE;
        base_address
    }

    fn find_library_path(&self, library_name: &str, requester_dir: &Path) -> Result<PathBuf> {
        let candidate_path = Path::new(library_name);
        if candidate_path.is_absolute() && candidate_path.exists() {
            return Ok(candidate_path.to_path_buf());
        }

        let mut candidates = Vec::new();
        if let Some(file_name) = candidate_path.file_name() {
            candidates.push(requester_dir.join(file_name));
        }
        candidates.push(requester_dir.join(library_name));
        candidates.push(PathBuf::from("/lib64").join(library_name));
        candidates.push(PathBuf::from("/usr/lib64").join(library_name));
        candidates.push(PathBuf::from("/lib/x86_64-linux-gnu").join(library_name));
        candidates.push(PathBuf::from("/usr/lib/x86_64-linux-gnu").join(library_name));
        candidates.push(PathBuf::from("/lib").join(library_name));
        candidates.push(PathBuf::from("/usr/lib").join(library_name));

        for candidate in candidates {
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(Error::DynamicLinker(format!(
            "Could not locate guest library {}",
            library_name
        )))
    }
}
