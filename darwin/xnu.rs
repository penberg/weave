use crate::{
    darwin::dyld::load_machfile,
    mmap::MappedFile,
    runtime::{CpuState, ExecutionContext},
};
use std::cell::Cell;
use tracing::trace;

thread_local! {
    static CURRENT_TASK: Cell<Option<*mut Task>> = Cell::new(None);
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

/// Represents a Darwin/XNU-style task (process)
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

    /// Execute a Mach-O binary using this task's settings
    ///
    /// This function loads a Mach-O binary, sets up the task state,
    /// and begins execution. It never returns.
    pub fn execve(&mut self, path: &str) -> ! {
        // Open and parse the Mach-O file
        let file = MappedFile::open(path).expect("failed to open file");
        let macho = load_machfile(file).expect("failed to parse Mach-O");

        // Find executable sections bounds (include __text, __stubs, etc.)
        let executable_sections: Vec<_> = macho
            .sections
            .iter()
            .filter(|section| section.segname == "__TEXT")
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
        self.context.state.pc = macho.entry_point;
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
}

/// Execute a file.
///
/// This implements the execve() system call, with a slight modification: instead of probing
/// the Mach-O header to determine if it needs dynamic linking and then calling into userspace
/// dyld, we always implement the dyld path since we're already running in userspace.
///
/// This function loads a Mach-O binary, processes dynamic linking requirements, sets up the
/// task state, and begins execution. It never returns.
pub fn execve(path: &str) -> ! {
    let task = unsafe { &mut *get_current_task() };
    task.execve(path)
}

const SYSCALL_EXIT: u32 = 1;

pub fn syscall(state: &CpuState, svc_imm: u16) {
    // For XNU on ARM64, we only support SVC #0x80 (Unix syscalls)
    assert_eq!(svc_imm, 0x80, "Unsupported SVC immediate: {:#x}", svc_imm);

    let syscall_num = state.regs[16] as u32;
    trace!(
        "XNU syscall: {} (x0={}, x16={}, svc_imm={:#x})",
        syscall_num, state.regs[0], state.regs[16], svc_imm
    );
    match syscall_num {
        SYSCALL_EXIT => {
            let exit_code = state.regs[0] as i32;
            trace!("XNU syscall: exit({})", exit_code);
            std::process::exit(exit_code);
        }
        _ => {
            todo!("unsupported xnu syscall: {}", syscall_num);
        }
    }
}
