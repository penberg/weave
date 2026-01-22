use crate::{
    mmap::MappedFile,
    runtime::{CpuState, ExecutionContext},
    sys::darwin::dyld::load_machfile,
};
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
    pub fn execve(&mut self, path: &str, argv: &[&str]) -> ! {
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

        // Initialize shared cache symbol discovery
        super::dyld::cache::init_shared_cache_symbols();

        // Note: We intentionally do NOT extend text bounds to include shared cache.
        // Shared cache functions (printf, malloc, etc.) should be executed as native
        // supervisor code, not translated. This is essential for correct variadic
        // function handling and other ABI requirements.

        // Set up guest stack with argc/argv
        // Allocate a stack region in guest address space
        let stack_size: usize = 8 * 1024 * 1024; // 8MB stack

        // Map the stack - let the kernel choose an available address to avoid conflicts
        let stack_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                stack_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if stack_ptr == libc::MAP_FAILED {
            panic!("Failed to allocate guest stack");
        }
        let stack_base = stack_ptr as u64;
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

        // Set up initial register state for main()
        // On ARM64: x0 = argc, x1 = argv
        self.context.state.regs[0] = argv.len() as u64; // argc
        self.context.state.regs[1] = argv_ptr; // argv
        self.context.state.regs[29] = sp; // frame pointer
        // Note: sp is set dynamically when guest code runs, not stored in regs

        trace!("Entry point: 0x{:016x}", self.context.state.pc);
        trace!(
            "Text section bounds: 0x{:016x} - 0x{:016x}",
            text_start, text_end
        );
        trace!(
            "Initial state: x0(argc)={}, x1(argv)=0x{:x}",
            argv.len(),
            argv_ptr
        );

        // Run the program - this never returns
        // The process will exit when main() returns or when exit() is called
        self.context.run()
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
pub fn execve(path: &str, argv: &[&str]) -> ! {
    let task = unsafe { &mut *get_current_task() };
    task.execve(path, argv)
}

const SYSCALL_EXIT: u32 = 1;
const SYSCALL_WRITE: u32 = 4;
const SYSCALL_SIGACTION: u32 = 46;
const SYSCALL_SIGPROCMASK: u32 = 48;
const SYSCALL_SIGALTSTACK: u32 = 53;
const SYSCALL_IOCTL: u32 = 54;
const SYSCALL_MUNMAP: u32 = 73;
const SYSCALL_MPROTECT: u32 = 74;
const SYSCALL_FCNTL: u32 = 92;
const SYSCALL_SIGRETURN: u32 = 184;
const SYSCALL_MMAP: u32 = 197;
const SYSCALL_SYSCTL: u32 = 202;
const SYSCALL_PTHREAD_CANCELED: u32 = 333;
const SYSCALL_FSTAT64: u32 = 339;
const SYSCALL_CSOPS_AUDITTOKEN: u32 = 170;
const SYSCALL_ABORT_WITH_PAYLOAD: u32 = 521;

// Mach traps (negative syscall numbers)
const MACH_TRAP_SEMAPHORE_SIGNAL: i32 = -63;

/// XNU ARM64 syscall error convention:
/// - On success: carry flag clear, x0 = return value
/// - On error: carry flag set, x0 = errno
const NZCV_CARRY_FLAG: u32 = 1 << 29;

/// Set syscall success: clear carry flag, set return value
fn syscall_success(state: &mut CpuState, ret: u64) {
    state.regs[0] = ret;
    state.nzcv &= !NZCV_CARRY_FLAG;
}

/// Set syscall error: set carry flag, set errno
fn syscall_error(state: &mut CpuState, errno: i32) {
    state.regs[0] = errno as u64;
    state.nzcv |= NZCV_CARRY_FLAG;
}

/// Handle libc-style return value (-1 on error with errno set)
fn syscall_libc_result(state: &mut CpuState, ret: isize) {
    if ret == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        syscall_error(state, errno);
    } else {
        syscall_success(state, ret as u64);
    }
}

pub fn syscall(state: &mut CpuState, svc_imm: u16) {
    // For XNU on ARM64, we only support SVC #0x80 (Unix/Mach syscalls)
    assert_eq!(svc_imm, 0x80, "Unsupported SVC immediate: {:#x}", svc_imm);

    // On XNU ARM64, x16 contains the syscall number:
    // - Positive numbers are Unix syscalls
    // - Negative numbers are Mach traps
    let syscall_num_signed = state.regs[16] as i64;

    // Check for Mach traps (negative syscall numbers)
    if syscall_num_signed < 0 {
        let trap_num = syscall_num_signed as i32;
        trace!(
            "XNU Mach trap: {} (x0={}, x16={:#x}, svc_imm={:#x})",
            trap_num, state.regs[0], state.regs[16], svc_imm
        );
        match trap_num {
            MACH_TRAP_SEMAPHORE_SIGNAL => {
                // semaphore_signal_trap(mach_port_name_t signal_name)
                // Signals a semaphore - used by pthread for synchronization
                let signal_name = state.regs[0] as u32;
                trace!("Mach trap: semaphore_signal_trap({})", signal_name);
                // Stub: return success (KERN_SUCCESS = 0)
                // This is safe to stub during cleanup/exit paths
                syscall_success(state, 0);
            }
            _ => {
                todo!("unsupported Mach trap: {}", trap_num);
            }
        }
        return;
    }

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
        SYSCALL_WRITE => {
            let fd = state.regs[0] as i32;
            let buf = state.regs[1] as *const u8;
            let count = state.regs[2] as usize;
            trace!("XNU syscall: write({}, {:?}, {})", fd, buf, count);
            let ret = unsafe { libc::write(fd, buf as *const libc::c_void, count) };
            syscall_libc_result(state, ret);
        }
        SYSCALL_SIGACTION => {
            let signum = state.regs[0] as i32;
            let act = state.regs[1];
            let oldact = state.regs[2] as *mut u8;
            trace!(
                "XNU syscall: sigaction({}, 0x{:x}, {:?})",
                signum, act, oldact
            );
            // TODO: Implement proper guest signal handling
            // For now, return success without actually setting handlers
            // If oldact is provided, zero it out to indicate no previous handler
            if !oldact.is_null() {
                unsafe {
                    // Zero out the old action struct (size of sigaction on ARM64 Darwin)
                    std::ptr::write_bytes(oldact, 0, 16);
                }
            }
            syscall_success(state, 0);
        }
        SYSCALL_SIGPROCMASK => {
            let how = state.regs[0] as i32;
            let set = state.regs[1] as *const libc::sigset_t;
            let oldset = state.regs[2] as *mut libc::sigset_t;
            trace!("XNU syscall: sigprocmask({}, {:?}, {:?})", how, set, oldset);
            let ret = unsafe { libc::sigprocmask(how, set, oldset) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_FCNTL => {
            let fd = state.regs[0] as i32;
            let cmd = state.regs[1] as i32;
            let arg = state.regs[2] as i64;
            trace!("XNU syscall: fcntl({}, {}, {})", fd, cmd, arg);
            let ret = unsafe { libc::fcntl(fd, cmd, arg) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_SIGRETURN => {
            // sigreturn restores context after signal handler - stub for now
            // This is called by longjmp when restoring signal masks
            debug!("XNU syscall: sigreturn (stub - returning 0)");
            syscall_success(state, 0);
        }
        SYSCALL_SYSCTL => {
            let name = state.regs[0] as *mut i32;
            let namelen = state.regs[1] as u32;
            let oldp = state.regs[2] as *mut libc::c_void;
            let oldlenp = state.regs[3] as *mut usize;
            let newp = state.regs[4] as *mut libc::c_void;
            let newlen = state.regs[5] as usize;
            trace!(
                "XNU syscall: sysctl({:?}, {}, {:?}, {:?}, {:?}, {})",
                name, namelen, oldp, oldlenp, newp, newlen
            );
            let ret = unsafe { libc::sysctl(name, namelen, oldp, oldlenp, newp, newlen) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_PTHREAD_CANCELED => {
            // __pthread_canceled(action) - pthread cancellation check
            // For now, just return 0 (no cancellation pending)
            trace!("XNU syscall: __pthread_canceled({})", state.regs[0]);
            syscall_success(state, 0);
        }
        SYSCALL_FSTAT64 => {
            let fd = state.regs[0] as i32;
            let buf = state.regs[1] as *mut libc::stat;
            trace!("XNU syscall: fstat64({}, {:?})", fd, buf);
            let ret = unsafe { libc::fstat(fd, buf) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_MUNMAP => {
            let addr = state.regs[0] as *mut libc::c_void;
            let len = state.regs[1] as libc::size_t;
            trace!("XNU syscall: munmap({:?}, {})", addr, len);
            let ret = unsafe { libc::munmap(addr, len) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_SIGALTSTACK => {
            let ss = state.regs[0] as *const libc::stack_t;
            let old_ss = state.regs[1] as *mut libc::stack_t;
            trace!("XNU syscall: sigaltstack({:?}, {:?})", ss, old_ss);
            let ret = unsafe { libc::sigaltstack(ss, old_ss) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_IOCTL => {
            let fd = state.regs[0] as libc::c_int;
            let request = state.regs[1] as libc::c_ulong;
            let arg = state.regs[2];
            trace!("XNU syscall: ioctl({}, 0x{:x}, 0x{:x})", fd, request, arg);
            let ret = unsafe { libc::ioctl(fd, request, arg) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_MPROTECT => {
            let addr = state.regs[0] as *mut libc::c_void;
            let len = state.regs[1] as libc::size_t;
            let prot = state.regs[2] as libc::c_int;
            trace!("XNU syscall: mprotect({:?}, {}, {})", addr, len, prot);
            let ret = unsafe { libc::mprotect(addr, len, prot) };
            syscall_libc_result(state, ret as isize);
        }
        SYSCALL_CSOPS_AUDITTOKEN => {
            // csops_audittoken - code signing operations with audit token
            // We stub this to return success for now
            let pid = state.regs[0] as i32;
            let ops = state.regs[1] as u32;
            trace!(
                "XNU syscall: csops_audittoken({}, {}, ...) - stub",
                pid, ops
            );
            syscall_success(state, 0);
        }
        SYSCALL_MMAP => {
            let addr = state.regs[0] as *mut libc::c_void;
            let len = state.regs[1] as libc::size_t;
            let prot = state.regs[2] as libc::c_int;
            let flags = state.regs[3] as libc::c_int;
            let fd = state.regs[4] as libc::c_int;
            let offset = state.regs[5] as libc::off_t;
            trace!(
                "XNU syscall: mmap({:?}, {}, {}, {}, {}, {})",
                addr, len, prot, flags, fd, offset
            );
            let ret = unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
            if ret == libc::MAP_FAILED {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                syscall_error(state, errno);
            } else {
                syscall_success(state, ret as u64);
            }
        }
        SYSCALL_ABORT_WITH_PAYLOAD => {
            let reason_namespace = state.regs[0] as u32;
            let reason_code = state.regs[1];
            let reason_string = state.regs[4] as *const i8;
            let msg = if !reason_string.is_null() {
                unsafe { std::ffi::CStr::from_ptr(reason_string) }
                    .to_string_lossy()
                    .to_string()
            } else {
                String::from("<no message>")
            };
            eprintln!(
                "abort_with_payload: namespace={}, code={}, message={}",
                reason_namespace, reason_code, msg
            );
            std::process::abort();
        }
        _ => {
            todo!("unsupported xnu syscall: {}", syscall_num);
        }
    }
}
