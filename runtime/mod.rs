//! Runtime execution engine for dynamic binary translation.
//!
//! This module provides the core JIT compilation and execution infrastructure for Weave,
//! a dynamic binary translator. It implements a Just-In-Time (JIT) compilation system that
//! translates guest instructions into host-native code at runtime.
//!
//! # Architecture
//!
//! The runtime uses a block-based translation approach:
//! - **Basic Blocks**: Guest code is translated one basic block at a time
//! - **Code Cache**: Translated blocks are cached to avoid re-translation
//! - **Dispatcher**: A low-level dispatcher manages transitions between translated blocks
//! - **Execution Context**: Each execution maintains its own CPU state and code cache
//!
//! # Platform Support
//!
//! The runtime supports multiple architectures through conditional compilation:
//! - **x86-64**: Full support for x86-64 guest code on x86-64 hosts
//! - **AArch64**: Support for ARM64 guest code on ARM64 hosts
//!
//! The `arch` module alias provides a unified interface to the current platform's
//! architecture-specific implementation.

use std::cell::Cell;
use std::collections::BTreeMap;

#[cfg(target_arch = "aarch64")]
pub mod arm64;

#[cfg(target_arch = "aarch64")]
pub use arm64 as arch;

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86 as arch;

pub mod random;
pub mod time;

pub use arch::{CpuState, TextAllocator, TranslatedBlock, flush_icache_range};

/// Execution context.
///
/// The execution context is used to store the CPU state, code cache, text
/// allocator, and other runtime information, which is used to execute the
/// guest code.
pub struct ExecutionContext {
    /// CPU register state
    pub state: CpuState,

    /// Code cache.
    ///
    /// The code cache is per execution context for thread safety.
    pub code_cache: BTreeMap<u64, TranslatedBlock>,

    /// Text allocator for JIT code
    pub text_allocator: TextAllocator,

    /// Whether to print translated code
    pub print_code: bool,

    /// Text segment start
    pub text_start: u64,

    /// Text segment end
    pub text_end: u64,

    /// Syscall handler.
    ///
    /// This function is called when guest executes a system call.
    pub syscall_handler: fn(&mut CpuState, u16),

    /// Supervisor stack.
    ///
    /// This stack is separate from the application stack and is used by the
    /// dispatcher and runtime code only.
    pub supervisor_stack: *mut u8,
}

impl ExecutionContext {
    const SUPERVISOR_STACK_SIZE: usize = 1024 * 1024; // 1 MB supervisor stack

    pub fn new(print_code: bool, syscall_handler: fn(&mut CpuState, u16)) -> Self {
        let supervisor_stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                Self::SUPERVISOR_STACK_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if supervisor_stack == libc::MAP_FAILED {
            panic!("Failed to allocate supervisor stack");
        }

        // Initialize the supervisor stack in the dispatcher assembly
        #[cfg(target_arch = "x86_64")]
        unsafe {
            arch::dispatcher::init_supervisor_stack(
                supervisor_stack as *mut u8,
                Self::SUPERVISOR_STACK_SIZE,
            );
        }

        let hint = arch::code_cache_hint();
        Self {
            state: CpuState::new(),
            code_cache: BTreeMap::new(),
            text_allocator: TextAllocator::new(hint),
            print_code,
            text_start: 0,
            text_end: 0,
            syscall_handler,
            supervisor_stack: supervisor_stack as *mut u8,
        }
        // Note: We don't initialize state.regs[4] (RSP) here because the application
        // will use the natural program stack that the OS provided. When we jump to
        // translated code, RSP will already be valid from the Rust runtime.
    }

    /// Run execution - this never returns!
    ///
    /// The process will exit when main() returns or when exit() is called.
    pub fn run(&mut self) -> ! {
        arch::translate_and_run(self, true)
    }
}

// Thread-local current execution context
thread_local! {
    static CURRENT_CONTEXT: Cell<Option<*mut ExecutionContext>> = const { Cell::new(None) };
}

/// Set the current execution context for this thread
pub fn set_current_context(ctx: *mut ExecutionContext) {
    CURRENT_CONTEXT.with(|c| c.set(Some(ctx)));
}

/// Get the current execution context for this thread
pub fn get_current_context() -> &'static mut ExecutionContext {
    let ctx_ptr = CURRENT_CONTEXT.with(|c| c.get().expect("no current execution context set"));
    unsafe { &mut *ctx_ptr }
}

/// Try to get the current execution context for this thread.
/// Returns None if no context has been set.
/// This is safe to call from signal handlers on the same thread.
pub fn try_get_current_context() -> Option<&'static mut ExecutionContext> {
    CURRENT_CONTEXT.with(|c| c.get().map(|ptr| unsafe { &mut *ptr }))
}
