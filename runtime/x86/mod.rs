mod assembler;
pub mod dispatcher;
pub mod signal;
pub mod translate;

pub use translate::{TranslatedBlock, translate_block};

use crate::Result;
use std::sync::atomic::AtomicU64;
use tracing::trace;

// Time tick counter for deterministic time simulation
pub static TIME_TICK: AtomicU64 = AtomicU64::new(0);

pub const X86_MAX_INSN_SIZE: usize = 15;

/// Start execution of an execution context
pub fn translate_and_run(
    ctx: &mut crate::runtime::ExecutionContext,
    returnable: bool,
) -> Result<i32> {
    crate::runtime::set_current_context(ctx as *mut crate::runtime::ExecutionContext);

    let entry_point = ctx.state.pc;
    trace!(
        "Starting direct execution from entry point: 0x{:016x}",
        entry_point
    );
    translate_and_branch_to(ctx, entry_point, returnable)
}

/// Translate a basic block and branch directly to it
pub fn translate_and_branch_to(
    ctx: &mut crate::runtime::ExecutionContext,
    address: u64,
    returnable: bool,
) -> Result<i32> {
    let block = translate_block(ctx, address, ctx.text_end, returnable)?;
    if ctx.print_code {
        block.print_code();
    }
    let target_addr = if returnable {
        block.execute_returnable(&mut ctx.state)
    } else {
        block.execute_direct(&mut ctx.state);
    };
    Ok(target_addr)
}

/// Allocates memory for the text segment
pub struct TextAllocator {
    /// The allocated text segment
    base: *mut u8,
    /// First free address
    first_free: usize,
}

impl TextAllocator {
    const MAX_SIZE: usize = 0x10000000;

    pub fn new() -> Self {
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                Self::MAX_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            panic!("Failed to allocate text segment");
        }
        Self {
            base: base as *mut u8,
            first_free: 0,
        }
    }

    pub fn start(&self) -> *mut u8 {
        unsafe { self.base.add(self.first_free) }
    }

    pub fn reserve(&mut self, size: usize) -> *mut u8 {
        let addr = unsafe { self.base.add(self.first_free) };
        self.first_free += size;
        addr
    }
}

/// x86-64 CPU state
///
/// This layout matches exactly what's on the stack in dispatcher.S:
/// RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15, RFLAGS, (padding)
#[derive(Debug)]
#[repr(C)]
pub struct CpuState {
    /// General-purpose registers (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15)
    pub regs: [u64; 16],

    /// RFLAGS register
    pub rflags: u64,

    /// Program counter (RIP) - not saved during syscalls, used for block execution
    pub pc: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuState {
    pub fn new() -> Self {
        Self {
            regs: [0; 16],
            pc: 0,
            rflags: 0x202, // IF flag set
        }
    }
}

/// Flush the instruction cache for the given range
pub fn flush_icache_range(_start: *const u8, _size: usize) {
    // x86-64 has coherent I-cache, no flush needed
    // But we add a memory barrier for safety
    unsafe {
        std::arch::asm!("mfence");
    }
}
