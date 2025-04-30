mod assembler;
pub mod dispatcher;
pub mod translate;

pub use translate::{TranslatedBlock, translate_block};

use crate::Result;
use std::sync::atomic::AtomicU64;
use tracing::trace;

// Time tick counter for deterministic time simulation
pub static TIME_TICK: AtomicU64 = AtomicU64::new(0);

pub const ARM64_INSN_SIZE: usize = 4;

/// Start execution of an execution context - this never returns!
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

/// Allocates memory for the text segment.
pub struct TextAllocator {
    /// The allocated text segment.
    base: *mut u8,
    /// First free address.
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
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
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
        unsafe { pthread_jit_write_protect_np(0) };
        unsafe { self.base.add(self.first_free) }
    }

    pub fn reserve(&mut self, size: usize) -> *mut u8 {
        let addr = unsafe { self.base.add(self.first_free) };
        self.first_free += size;
        unsafe { pthread_jit_write_protect_np(1) };
        addr
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CpuState {
    /// General-purpose registers.
    pub regs: [u64; 31],

    /// Program counter.
    pub pc: u64,

    /// NZCV flags register
    pub nzcv: u32,

    /// Floating-point Control Register
    pub fpcr: u32,

    /// Floating-point Status Register
    pub fpsr: u32,

    /// Padding to maintain alignment
    _padding: u32,

    /// NEON/SIMD vector registers (Q0-Q31)
    /// Each Q register is 128 bits (16 bytes), represented as two u64 values
    pub vregs: [[u64; 2]; 32],
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuState {
    pub fn new() -> Self {
        Self {
            regs: [0; 31],
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            _padding: 0,
            vregs: [[0; 2]; 32],
        }
    }
}

/// Flush the instruction cache for the given range using macOS system call
pub fn flush_icache_range(start: *const u8, size: usize) {
    // Use macOS sys_icache_invalidate system call for reliable I-cache flushing
    unsafe {
        sys_icache_invalidate(start as *mut libc::c_void, size);

        // Additional barriers for extra safety
        std::arch::asm!("dsb sy");
        std::arch::asm!("isb");
    }
}

unsafe extern "C" {
    pub(crate) fn pthread_jit_write_protect_np(enabled: libc::c_int);
    pub(crate) fn sys_icache_invalidate(start: *mut libc::c_void, size: libc::size_t);
}
