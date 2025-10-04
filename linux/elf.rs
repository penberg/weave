use crate::mmap::MappedFile;
use goblin::elf::Elf;
use std::fmt::Display;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum ElfError {
    #[error("not an ELF file")]
    NotElf,
    #[error("goblin parse error: {0}")]
    GoblinError(#[from] goblin::error::Error),
    #[error("unsupported architecture")]
    UnsupportedArch,
    #[error("text segment is missing")]
    MissingTextSegment,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Arch {
    X86_64,
}

impl Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "X86_64"),
        }
    }
}

pub struct Segment {
    pub addr: u64,
    pub size: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub prot: libc::c_int,
}

pub struct Section {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub executable: bool,
}

pub struct ElfFile {
    pub arch: Arch,
    pub entry_point: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub file: MappedFile,
}

// Base address for loading ELF binaries
const ELF_BASE_ADDRESS: u64 = 0x0000000200000000;

pub fn load_elf(file: MappedFile) -> Result<ElfFile, ElfError> {
    let elf_file = parse_elf(file)?;
    load_segments(&elf_file);
    Ok(elf_file)
}

fn parse_elf(file: MappedFile) -> Result<ElfFile, ElfError> {
    let elf = Elf::parse(&file.data)?;

    // Check architecture
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Err(ElfError::UnsupportedArch);
    }

    let arch = Arch::X86_64;

    // Parse program headers (segments)
    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            let mut prot: libc::c_int = 0;
            if ph.p_flags & goblin::elf::program_header::PF_R != 0 {
                prot |= libc::PROT_READ;
            }
            if ph.p_flags & goblin::elf::program_header::PF_W != 0 {
                prot |= libc::PROT_WRITE;
            }
            if ph.p_flags & goblin::elf::program_header::PF_X != 0 {
                prot |= libc::PROT_EXEC;
            }

            segments.push(Segment {
                addr: ph.p_vaddr + ELF_BASE_ADDRESS,
                size: ph.p_memsz,
                fileoff: ph.p_offset,
                filesize: ph.p_filesz,
                prot,
            });
        }
    }

    // Parse section headers
    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_size > 0 {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            let executable = sh.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0;

            sections.push(Section {
                name,
                addr: sh.sh_addr + ELF_BASE_ADDRESS,
                size: sh.sh_size,
                executable,
            });
        }
    }

    let entry_point = elf.entry + ELF_BASE_ADDRESS;

    Ok(ElfFile {
        arch,
        entry_point,
        segments,
        sections,
        file,
    })
}

fn load_segments(elf: &ElfFile) {
    let fd = elf.file.fd;
    for segment in &elf.segments {
        debug!(
            "Loading segment at 0x{:016x} ({} bytes) prot={:x}",
            segment.addr, segment.size, segment.prot
        );

        let prot = segment.prot & !libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_FIXED;
        let data = unsafe {
            libc::mmap(
                segment.addr as *mut libc::c_void,
                segment.size as usize,
                prot,
                flags,
                fd,
                segment.fileoff as libc::off_t,
            )
        };
        if data == libc::MAP_FAILED {
            panic!("Failed to map segment: {}", std::io::Error::last_os_error());
        }
    }
}
