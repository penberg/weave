mod assembler;
pub mod dispatcher;
pub mod signal;
pub mod translate;

pub use translate::{TranslatedBlock, translate_block};

use crate::Result;
use tracing::trace;

pub const X86_MAX_INSN_SIZE: usize = 15;

/// Code cache memory placement.
///
/// We place the code cache at a fixed location to ensure it's within ±2GB of
/// typical ELF text segments (loaded around 0x400000). This enables 32-bit
/// relative jumps/calls between guest code and our translated code cache.
const CODE_CACHE_BASE: u64 = 0x200000000; // 8GB
const CODE_CACHE_OFFSET: u64 = 0x10000000; // +256MB

/// Get the hint address for code cache placement.
pub fn code_cache_hint() -> *mut libc::c_void {
    (CODE_CACHE_BASE + CODE_CACHE_OFFSET) as *mut libc::c_void
}

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

    pub fn new(hint: *mut libc::c_void) -> Self {
        let base = unsafe {
            libc::mmap(
                hint,
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

// Register indices for CpuState.regs array
pub const REG_RAX: usize = 0;
pub const REG_RCX: usize = 1;
pub const REG_RDX: usize = 2;
pub const REG_RBX: usize = 3;
pub const REG_RSP: usize = 4;
pub const REG_RBP: usize = 5;
pub const REG_RSI: usize = 6;
pub const REG_RDI: usize = 7;
pub const REG_R8: usize = 8;
pub const REG_R9: usize = 9;
pub const REG_R10: usize = 10;
pub const REG_R11: usize = 11;
pub const REG_R12: usize = 12;
pub const REG_R13: usize = 13;
pub const REG_R14: usize = 14;
pub const REG_R15: usize = 15;

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
