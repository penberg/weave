/// glibc function implementations for Linux
///
/// This module provides implementations of glibc functions that are needed
/// by dynamically linked binaries, including:
/// - __libc_start_main: The main C runtime startup function
/// - Various stub functions for optional glibc features
use tracing::debug;

/// Implementation of __libc_start_main
/// This function is called by the _start entry point with:
/// - rdi: address of main()
/// - rsi: argc
/// - rdx: argv
/// - rcx: init function (can be NULL)
/// - r8: fini function (can be NULL)
/// - r9: rtld_fini function (can be NULL)
/// - stack: stack_end
///
/// This implementation:
/// 1. Sets up the CPU state with proper arguments for main()
/// 2. Uses translate_and_branch_to to jump to the emulated main()
/// 3. Exits with main's return value
#[unsafe(no_mangle)]
pub extern "C" fn libc_start_main(
    main_addr: u64,
    argc: i32,
    argv: *const *const u8,
    _init: u64,
    _fini: u64,
    _rtld_fini: u64,
    _stack_end: *const (),
) -> ! {
    use crate::sys::linux::{get_current_task, kernel::Task};

    debug!(
        "__libc_start_main called: main=0x{:x}, argc={}",
        main_addr, argc
    );

    // Get the current task and its execution context
    let task = unsafe { &mut *(get_current_task() as *mut Task) };

    // Set up CPU state for main(argc, argv, envp)
    // x86-64 calling convention: rdi, rsi, rdx for first 3 args
    task.context.state.regs[7] = argc as u64; // RDI: argc
    task.context.state.regs[6] = argv as u64; // RSI: argv
    task.context.state.regs[2] = 0; // RDX: envp (NULL)

    // Jump to main() using the JIT
    let exit_code = crate::runtime::x86::translate_and_branch_to(
        &mut task.context,
        main_addr,
        true, // returnable - main() will return
    )
    .unwrap_or_else(|e| {
        eprintln!("Error executing main: {}", e);
        1
    });

    debug!("main() returned with exit code: {}", exit_code);
    std::process::exit(exit_code);
}

/// Stub implementation of __gmon_start__
/// This is for profiling support, we can just make it a no-op
pub extern "C" fn gmon_start() {
    debug!("__gmon_start__ called (no-op)");
}

/// Stub implementation for transactional memory symbols
/// These are weak symbols used by GCC's transactional memory support
pub extern "C" fn itm_stub() {
    debug!("ITM stub called (no-op)");
}

/// Stub implementation of __cxa_finalize
/// This is for C++ destructor registration, can be a no-op for simple programs
pub extern "C" fn cxa_finalize(_dso_handle: *const ()) {
    debug!("__cxa_finalize called (no-op)");
}
