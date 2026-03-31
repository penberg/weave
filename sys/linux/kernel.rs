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
    pub fn execve(
        &mut self,
        path: &str,
        argv: &[&str],
        envp: &[String],
    ) -> Result<std::convert::Infallible, crate::Error> {
        // Open and parse the ELF file
        let file = MappedFile::open(path).map_err(|e| exec_error(path, e))?;
        let elf = load_elf(file, ELF_BASE_ADDRESS).map_err(|e| exec_error(path, e))?;

        // Check if this is a dynamically linked binary
        let parsed_elf = Elf::parse(elf.file.data).map_err(|e| crate::Error::Exec {
            path: path.to_string(),
            message: e.to_string(),
        })?;
        let is_dynamic = parsed_elf.dynamic.is_some();

        let (entry_point, lib_text_bounds) = if is_dynamic {
            debug!("Dynamically linked binary detected, running dynamic linker");
            let mut linker = DynamicLinker::new();

            // Load dependencies (including libc) into guest address space
            linker
                .load_executable(path, &elf)
                .map_err(|e| crate::Error::Exec {
                    path: path.to_string(),
                    message: format!("failed to load dependencies: {}", e),
                })?;

            // Compute TLS layout before relocation (R_X86_64_TPOFF64 needs it)
            linker.setup_tls(&elf);

            // Compute text bounds before relocation so that IFUNC resolvers
            // can translate and execute code via translate_and_call.
            let lib_bounds = linker.get_library_text_bounds();

            // Compute executable text bounds (same logic as below, but needed early)
            let exec_sections: Vec<_> = elf
                .sections
                .iter()
                .filter(|section| section.executable)
                .collect();
            let (mut early_text_start, mut early_text_end) = if exec_sections.is_empty() {
                (0, u64::MAX)
            } else {
                let start = exec_sections.iter().map(|s| s.addr).min().unwrap();
                let end = exec_sections.iter().map(|s| s.addr + s.size).max().unwrap();
                (start, end)
            };
            let (lib_start, lib_end) = lib_bounds;
            if lib_start < early_text_start {
                early_text_start = lib_start;
            }
            if lib_end > early_text_end {
                early_text_end = lib_end;
            }

            // Set text bounds and current context before relocation so that
            // IFUNC resolvers (R_X86_64_IRELATIVE) can use translate_and_call.
            self.context.text_start = early_text_start;
            self.context.text_end = early_text_end;
            crate::runtime::set_current_context(
                &mut self.context as *mut crate::runtime::ExecutionContext,
            );

            // Allocate a temporary stack for IFUNC resolvers during relocation.
            // The real guest stack is set up later, but IFUNC resolvers need a
            // valid stack to execute.
            let ifunc_stack_size: usize = 64 * 1024; // 64KB is plenty
            let ifunc_stack_base: u64 = 0x7ffe00000000;
            let ifunc_stack_ptr = unsafe {
                libc::mmap(
                    ifunc_stack_base as *mut libc::c_void,
                    ifunc_stack_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if ifunc_stack_ptr == libc::MAP_FAILED {
                panic!("Failed to allocate IFUNC resolver stack");
            }
            // Stack grows down; point near the top, 16-byte aligned.
            // Leave space at the top because execute_callable writes to [RSP].
            self.context.state.regs[crate::runtime::x86::REG_RSP] =
                (ifunc_stack_base + ifunc_stack_size as u64) - 16;

            // Perform relocations
            linker.relocate(&elf).map_err(|e| crate::Error::Exec {
                path: path.to_string(),
                message: format!("failed to relocate: {}", e),
            })?;

            // Free temporary IFUNC resolver stack and clear code cache.
            // IFUNC resolver blocks were translated with returnable=true; they
            // must not be reused during normal execution which may need different
            // translation.
            unsafe {
                libc::munmap(ifunc_stack_ptr, ifunc_stack_size);
            }
            self.context.code_cache.clear();

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

        // First, write all the environment strings and collect their addresses
        let mut env_addrs: Vec<u64> = Vec::with_capacity(envp.len());
        for env_var in envp {
            let bytes = env_var.as_bytes();
            sp -= (bytes.len() + 1) as u64; // +1 for null terminator
            // Align to 8 bytes
            sp &= !7;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), sp as *mut u8, bytes.len());
                *((sp + bytes.len() as u64) as *mut u8) = 0; // null terminator
            }
            env_addrs.push(sp);
        }

        // Write all the argument strings and collect their addresses
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

        // The Linux ABI requires SP to be 16-byte aligned when _start runs.
        // Total 8-byte entries: 1 (argc) + argc + 1 (argv NULL) + envp_count + 1 (envp NULL)
        // If odd, we need one padding entry to maintain 16-byte alignment.
        let total_entries = 1 + argv.len() + 1 + envp.len() + 1;
        if total_entries % 2 != 0 {
            sp -= 8;
            unsafe {
                *(sp as *mut u64) = 0;
            }
        }

        // Push NULL terminator for envp array
        sp -= 8;
        unsafe {
            *(sp as *mut u64) = 0;
        }

        // Push envp pointers in reverse order
        for addr in env_addrs.iter().rev() {
            sp -= 8;
            unsafe {
                *(sp as *mut u64) = *addr;
            }
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
pub fn execve(
    path: &str,
    argv: &[&str],
    envp: &[String],
) -> Result<std::convert::Infallible, crate::Error> {
    let task = unsafe { &mut *get_current_task() };
    task.execve(path, argv, envp)
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

    // Even without a PT_TLS segment, we need a minimal TLS area because
    // glibc uses fs:0x28 for the stack canary. The TCB must be large enough
    // to cover at least offset 0x28 + 8 = 0x30 bytes past the FS base.
    let (tls_memsz, tls_filesz, tls_align) = match tls_phdr {
        Some(ph) => (
            ph.p_memsz as usize,
            ph.p_filesz as usize,
            std::cmp::max(ph.p_align as usize, 16),
        ),
        None => (0, 0, 16),
    };

    // Total allocation: aligned TLS block + TCB
    // The TCB needs at least 0x30 bytes for the self-pointer (offset 0)
    // and stack canary (offset 0x28).
    let tcb_size = 0x30;
    let tls_block_size = (tls_memsz + tls_align - 1) & !(tls_align - 1);
    let total_size = tls_block_size + tcb_size;

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
    if let Some(phdr) = tls_phdr {
        if tls_filesz > 0 {
            let src = (phdr.p_vaddr + ELF_BASE_ADDRESS) as *const u8;
            // TLS data goes at the start of the TLS block
            // In variant II, TLS variables are at negative offsets from TCB
            let dst = unsafe { tcb_addr.sub(tls_memsz) };
            unsafe {
                std::ptr::copy_nonoverlapping(src, dst, tls_filesz);
            }
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

fn exec_error(path: &str, err: crate::Error) -> crate::Error {
    let message = match &err {
        crate::Error::Io(io_err) => crate::io_error_message(io_err),
        _ => err.to_string(),
    };
    crate::Error::Exec {
        path: path.to_string(),
        message,
    }
}
