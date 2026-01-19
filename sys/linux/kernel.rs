use crate::{
    mmap::MappedFile,
    runtime::{CpuState, ExecutionContext},
    sys::linux::elf::{ELF_BASE_ADDRESS, load_elf},
    sys::linux::ld_linux::DynamicLinker,
};
use goblin::elf::Elf;
use std::cell::Cell;
use tracing::{debug, trace};

thread_local! {
    static CURRENT_TASK: Cell<Option<*mut Task>> = const { Cell::new(None) };
}

/// Set the current task for this thread
pub fn set_current_task(task: *mut Task) {
    CURRENT_TASK.with(|t| t.set(Some(task)));
}

/// Get the current task for this thread
pub fn get_current_task() -> *mut Task {
    CURRENT_TASK.with(|t| t.get().expect("no current task set"))
}

pub struct TaskBuilder {
    print_code: bool,
}

impl Default for TaskBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskBuilder {
    pub fn new() -> Self {
        Self { print_code: false }
    }

    pub fn print_code(mut self, print_code: bool) -> Self {
        self.print_code = print_code;
        self
    }

    pub fn build(self) -> Task {
        Task::new(self.print_code)
    }
}

/// Represents a Linux task (process)
pub struct Task {
    /// Runtime execution context
    pub context: ExecutionContext,
}

impl Task {
    pub fn new(print_code: bool) -> Self {
        Self {
            context: ExecutionContext::new(print_code, syscall),
        }
    }

    /// Execute an ELF binary using this task's settings
    ///
    /// This function loads an ELF binary, sets up the task state,
    /// and begins execution. It never returns.
    pub fn execve(&mut self, path: &str, argv: &[&str]) -> ! {
        // Open and parse the ELF file
        let file = match MappedFile::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open {}: {}", path, e);
                std::process::exit(1);
            }
        };
        let elf = match load_elf(file) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to load ELF: {}", e);
                std::process::exit(1);
            }
        };

        // Check if this is a dynamically linked binary
        let parsed_elf = match Elf::parse(elf.file.data) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to parse ELF: {}", e);
                std::process::exit(1);
            }
        };
        let is_dynamic = parsed_elf.dynamic.is_some();

        let (entry_point, lib_text_bounds) = if is_dynamic {
            debug!("Dynamically linked binary detected, running dynamic linker");
            let mut linker = DynamicLinker::new();

            // Load dependencies (including libc) into guest address space
            if let Err(e) = linker.load_executable(&elf) {
                eprintln!("Failed to load dependencies: {}", e);
                std::process::exit(1);
            }

            // Perform relocations
            if let Err(e) = linker.relocate(&elf) {
                eprintln!("Failed to relocate: {}", e);
                std::process::exit(1);
            }

            // Get library text bounds for the dispatcher
            let lib_bounds = linker.get_library_text_bounds();

            debug!("Using ELF entry point (_start) at 0x{:x}", elf.entry_point);
            (elf.entry_point, Some(lib_bounds))
        } else {
            (elf.entry_point, None)
        };

        // Set up TLS (Thread-Local Storage) if the binary has a PT_TLS segment
        setup_tls(&parsed_elf);

        // Find executable sections bounds
        let executable_sections: Vec<_> = elf
            .sections
            .iter()
            .filter(|section| section.executable)
            .collect();

        let (mut text_start, mut text_end) = if executable_sections.is_empty() {
            (0, u64::MAX)
        } else {
            let start = executable_sections.iter().map(|s| s.addr).min().unwrap();
            let end = executable_sections
                .iter()
                .map(|s| s.addr + s.size)
                .max()
                .unwrap();
            (start, end)
        };

        // Extend text bounds to include loaded libraries
        if let Some((lib_start, lib_end)) = lib_text_bounds {
            if lib_start < text_start {
                text_start = lib_start;
            }
            if lib_end > text_end {
                text_end = lib_end;
            }
            debug!(
                "Text bounds extended to include libraries: 0x{:x} - 0x{:x}",
                text_start, text_end
            );
        }

        // Set up execution context
        self.context.state.pc = entry_point;
        self.context.text_start = text_start;
        self.context.text_end = text_end;

        // Set up guest stack with argc/argv
        // Allocate a stack region in guest address space
        let stack_size: usize = 8 * 1024 * 1024; // 8MB stack
        let stack_base: u64 = 0x7fff00000000; // Stack base address in guest space (high address)

        // Map the stack
        let stack_ptr = unsafe {
            libc::mmap(
                stack_base as *mut libc::c_void,
                stack_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if stack_ptr == libc::MAP_FAILED {
            panic!("Failed to allocate guest stack");
        }
        debug!(
            "Allocated guest stack at 0x{:x}, size {}",
            stack_base, stack_size
        );

        // Stack grows down, so start at the top of the stack
        let mut sp = stack_base + stack_size as u64;

        // First, write all the argument strings and collect their addresses
        let mut arg_addrs: Vec<u64> = Vec::with_capacity(argv.len());
        for arg in argv {
            let bytes = arg.as_bytes();
            sp -= (bytes.len() + 1) as u64; // +1 for null terminator
            // Align to 8 bytes
            sp &= !7;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), sp as *mut u8, bytes.len());
                *((sp + bytes.len() as u64) as *mut u8) = 0; // null terminator
            }
            arg_addrs.push(sp);
            debug!("  argv[{}] at 0x{:x}: {:?}", arg_addrs.len() - 1, sp, arg);
        }

        // Align stack to 16 bytes
        sp &= !15;

        // Push NULL terminator for envp array (no environment variables)
        sp -= 8;
        unsafe {
            *(sp as *mut u64) = 0;
        }

        // Push NULL terminator for argv array
        sp -= 8;
        unsafe {
            *(sp as *mut u64) = 0;
        }

        // Push argv pointers in reverse order
        for addr in arg_addrs.iter().rev() {
            sp -= 8;
            unsafe {
                *(sp as *mut u64) = *addr;
            }
        }
        let argv_ptr = sp;

        // Push argc
        sp -= 8;
        unsafe {
            *(sp as *mut u64) = argv.len() as u64;
        }

        // Align to 16 bytes for ABI compliance
        sp &= !15;

        debug!(
            "Guest stack: sp=0x{:x}, argc={}, argv=0x{:x}",
            sp,
            argv.len(),
            argv_ptr
        );

        // Set RSP to our prepared stack
        self.context.state.regs[crate::runtime::x86::REG_RSP] = sp;

        trace!("Entry point: 0x{:016x}", self.context.state.pc);
        trace!(
            "Text section bounds: 0x{:016x} - 0x{:016x}",
            text_start, text_end
        );
        trace!(
            "Initial state: rsp=0x{:x}, argc={}, argv=0x{:x}",
            sp,
            argv.len(),
            argv_ptr
        );

        // Run the program - this never returns
        // The dispatcher handles control flow and calls process::exit() when the program terminates
        self.context.run()
    }
}

/// Execute a file
pub fn execve(path: &str, argv: &[&str]) -> ! {
    let task = unsafe { &mut *get_current_task() };
    task.execve(path, argv)
}

/// Set up Thread-Local Storage for the guest binary.
///
/// x86-64 Linux uses TLS variant II where the FS base points to the TCB
/// (Thread Control Block) at the end of the TLS block:
///
///   [TLS init image (memsz, aligned)] [TCB: self-pointer]
///                                      ^--- FS base
///
/// fs:0 returns the self-pointer (address of TCB itself).
/// fs:-offset accesses TLS variables at negative offsets from the TCB.
fn setup_tls(elf: &Elf) {
    use goblin::elf::program_header::PT_TLS;

    let tls_phdr = elf.program_headers.iter().find(|ph| ph.p_type == PT_TLS);
    let tls_phdr = match tls_phdr {
        Some(ph) => ph,
        None => return, // No TLS segment
    };

    let tls_memsz = tls_phdr.p_memsz as usize;
    let tls_filesz = tls_phdr.p_filesz as usize;
    let tls_align = std::cmp::max(tls_phdr.p_align as usize, 16);

    // Total allocation: aligned TLS block + TCB (8 bytes for self-pointer)
    // The TLS block is placed before the TCB, aligned to tls_align
    let tls_block_size = (tls_memsz + tls_align - 1) & !(tls_align - 1);
    let total_size = tls_block_size + 8; // +8 for TCB self-pointer

    // Allocate the TLS area
    let tls_area = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if tls_area == libc::MAP_FAILED {
        panic!("Failed to allocate TLS area");
    }

    let tls_base = tls_area as *mut u8;
    let tcb_addr = unsafe { tls_base.add(tls_block_size) };

    // Copy the TLS initialization image (the initialized data portion)
    // The init image is at p_vaddr + ELF_BASE_ADDRESS in the loaded guest
    if tls_filesz > 0 {
        let src = (tls_phdr.p_vaddr + ELF_BASE_ADDRESS) as *const u8;
        // TLS data goes at the start of the TLS block
        // In variant II, TLS variables are at negative offsets from TCB
        let dst = unsafe { tcb_addr.sub(tls_memsz) };
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, tls_filesz);
        }
    }

    // Zero the BSS portion (filesz..memsz is zero-initialized)
    if tls_memsz > tls_filesz {
        let bss_dst = unsafe { tcb_addr.sub(tls_memsz).add(tls_filesz) };
        unsafe {
            std::ptr::write_bytes(bss_dst, 0, tls_memsz - tls_filesz);
        }
    }

    // Write the self-pointer at the TCB (fs:0 returns this value)
    unsafe {
        *(tcb_addr as *mut u64) = tcb_addr as u64;
    }

    // Store the guest TLS base in a global so the translator can emit code
    // that loads from it instead of using fs:0 (which would access the host TLS).
    unsafe {
        GUEST_FS_BASE = tcb_addr as u64;
    }

    debug!(
        "TLS initialized: area={:p}, tcb={:p}, memsz={}, filesz={}, align={}",
        tls_base, tcb_addr, tls_memsz, tls_filesz, tls_align
    );
}

/// Guest FS base address (TLS pointer), used by the translator to replace fs:0 reads.
pub static mut GUEST_FS_BASE: u64 = 0;

const SYSCALL_EXIT: u64 = 60;

pub fn syscall(state: &mut CpuState, _syscall_insn: u16) {
    let syscall_num = state.regs[0]; // RAX contains syscall number
    trace!(
        "Linux syscall: {} (rax={}, rdi={})",
        syscall_num, state.regs[0], state.regs[7]
    );
    match syscall_num {
        SYSCALL_EXIT => {
            let exit_code = state.regs[7] as i32; // RDI contains first argument
            trace!("Linux syscall: exit({})", exit_code);
            std::process::exit(exit_code);
        }
        _ => {
            todo!("unsupported linux syscall: {}", syscall_num);
        }
    }
}
