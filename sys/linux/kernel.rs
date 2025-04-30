use crate::{
    Result,
    mmap::MappedFile,
    runtime::{CpuState, ExecutionContext},
    sys::linux::elf::load_elf,
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
    fn execve_impl(&mut self, path: &str) -> Result<()> {
        // Open and parse the ELF file
        let file = MappedFile::open(path)?;
        let elf = load_elf(file)?;

        // Check if this is a dynamically linked binary
        let parsed_elf = Elf::parse(elf.file.data).map_err(crate::ObjectFormatError::from)?;
        let is_dynamic = parsed_elf.dynamic.is_some();

        let entry_point = if is_dynamic {
            debug!("Dynamically linked binary detected, running dynamic linker");
            let mut linker = DynamicLinker::new();

            // Load dependencies
            linker.load_executable(&elf)?;

            // Perform relocations
            linker.relocate(&elf)?;

            // Use the ELF entry point (_start), which will call __libc_start_main,
            // which in turn will use translate_and_branch_to to jump to main()
            debug!("Using ELF entry point (_start) at 0x{:x}", elf.entry_point);
            elf.entry_point
        } else {
            elf.entry_point
        };

        // Find executable sections bounds
        let executable_sections: Vec<_> = elf
            .sections
            .iter()
            .filter(|section| section.executable)
            .collect();

        let (text_start, text_end) = if executable_sections.is_empty() {
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

        // Set up execution context
        self.context.state.pc = entry_point;
        self.context.text_start = text_start;
        self.context.text_end = text_end;

        trace!("Entry point: 0x{:016x}", self.context.state.pc);
        trace!(
            "Text section bounds: 0x{:016x} - 0x{:016x}",
            text_start, text_end
        );

        // Run the program and get the exit code
        let exit_code = self.context.run();
        trace!("Program exited with code: {}", exit_code);
        std::process::exit(exit_code);
    }

    /// Execute an ELF binary using this task's settings
    pub fn execve(&mut self, path: &str) -> ! {
        if let Err(e) = self.execve_impl(path) {
            eprintln!("Execution error: {}", e);
            std::process::exit(1);
        }
        unreachable!("execve_impl should never return Ok")
    }
}

/// Execute a file
pub fn execve(path: &str, _argv: &[&str]) -> ! {
    // TODO: Implement proper argc/argv stack setup for Linux
    let task = unsafe { &mut *get_current_task() };
    task.execve(path)
}

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
