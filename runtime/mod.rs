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

pub use arch::{CpuState, TextAllocator, TranslatedBlock, flush_icache_range};

/// Execution context that the runtime uses - independent of darwin/OS layer
pub struct ExecutionContext {
    /// CPU register state
    pub state: CpuState,

    /// Code cache - per execution context for thread safety
    pub code_cache: BTreeMap<u64, TranslatedBlock>,

    /// Text allocator for JIT code
    pub text_allocator: TextAllocator,

    /// Whether to print translated code
    pub print_code: bool,

    /// Text segment start
    pub text_start: u64,

    /// Text segment end
    pub text_end: u64,

    /// Syscall handler - called when guest executes syscall
    pub syscall_handler: fn(&CpuState, u16),
}

impl ExecutionContext {
    pub fn new(print_code: bool, syscall_handler: fn(&CpuState, u16)) -> Self {
        Self {
            state: CpuState::new(),
            code_cache: BTreeMap::new(),
            text_allocator: TextAllocator::new(),
            print_code,
            text_start: 0,
            text_end: 0,
            syscall_handler,
        }
    }

    /// Run execution - this can return if the main function returns
    pub fn run(&mut self) -> i32 {
        arch::translate_and_run(self, true).unwrap()
    }
}

// Thread-local current execution context
thread_local! {
    static CURRENT_CONTEXT: Cell<Option<*mut ExecutionContext>> = Cell::new(None);
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
