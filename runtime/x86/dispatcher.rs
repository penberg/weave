use crate::runtime::{
    self,
    x86::{CpuState, translate::translate_block},
};
use core::arch::global_asm;
use tracing::trace;

/// Handles control flow transitions between translated code blocks
///
/// # Safety
///
/// This function must be called from the dispatcher trampoline assembly with:
/// - `target_addr`: A valid guest or supervisor address to dispatch to
/// - `_stack_ptr`: Currently unused
///
/// The function assumes a valid execution context has been set up via
/// `set_current_context()` and accesses it without additional checks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn debug_saved_registers(saved_rsi: u64, saved_rdi: u64) {
    trace!(
        "DEBUG: Saved RSI=0x{:016x}, Saved RDI=0x{:016x}",
        saved_rsi, saved_rdi
    );
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn debug_pre_jump(rsi: u64, rdi: u64, rbx: u64, target: u64) {
    trace!(
        "PRE-JUMP: RSI=0x{:016x}, RDI=0x{:016x}, RBX=0x{:016x}, target=0x{:016x}",
        rsi, rdi, rbx, target
    );
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dispatcher(
    target_addr: usize,
    _stack_ptr: *mut u8,
    saved_rsi: u64,
    saved_rbx: u64,
    saved_rdi: u64,
    saved_r11: u64,
) -> usize {
    let ctx = runtime::get_current_context();

    crate::runtime::time::tick();

    let target_addr = target_addr as u64;

    // Special case: if target is 0, the program returned from main()
    // Exit with code 0
    if target_addr == 0 {
        trace!("Program returned from main(), exiting with code 0");
        std::process::exit(0);
    }

    let is_guest = target_addr >= ctx.text_start && target_addr < ctx.text_end;

    trace!(
        "Dispatching to 0x{:016x} ({}) saved_rdi=0x{:016x} saved_rsi=0x{:016x} saved_rbx=0x{:016x} saved_r11=0x{:016x}",
        target_addr,
        if is_guest { "guest" } else { "supervisor" },
        saved_rdi,
        saved_rsi,
        saved_rbx,
        saved_r11
    );

    if is_guest {
        ctx.state.pc = target_addr;

        let block = translate_block(ctx, target_addr, ctx.text_end, false).unwrap();

        if ctx.print_code {
            block.print_code();
        }

        trace!(
            "Returning translated block address: {:p}",
            block.text_start()
        );

        // Return the address of the translated code (skip first 8 bytes)
        unsafe { block.text_start().add(8) as usize }
    } else {
        // Target address is in supervisor code, but we need to translate
        // the return address if it points to guest code

        // The return address is on the application stack
        // When we entered the dispatcher, the guest code had already pushed
        // the return address (for a CALL instruction), then pushed saved_R10,
        // then the trampoline pushed saved_R15.
        // Stack layout: [..., return_addr, saved_R10, saved_R15] <- _stack_ptr
        // We need to read from _stack_ptr + 16 to get return_addr

        // Get the return address from the application stack (above saved R10 and R15)
        // _stack_ptr points to saved_R15, return_addr is 16 bytes above
        let return_addr_ptr = unsafe { (_stack_ptr as *mut u64).add(2) };
        let return_addr = unsafe { *return_addr_ptr };
        let is_return_guest = return_addr >= ctx.text_start && return_addr < ctx.text_end;

        if is_return_guest {
            trace!("Translating return address block: 0x{:016x}", return_addr);
            // Mark as returnable=true so that RET instructions execute naturally
            let return_block = translate_block(ctx, return_addr, ctx.text_end, true).unwrap();

            // Update return address on stack to point to translated code
            let translated_return_addr = unsafe { return_block.text_start().add(8) as u64 };
            unsafe { *return_addr_ptr = translated_return_addr };
            trace!(
                "Updated return address to translated: 0x{:016x}",
                translated_return_addr
            );
        }

        // Target address is in supervisor code, execute directly
        target_addr as usize
    }
}

/// Handles system call interception from translated guest code
///
/// # Safety
///
/// This function must be called from the syscall wrapper assembly with:
/// - `cpu_state`: A valid pointer to a CpuState structure on the supervisor stack
///
/// The caller must ensure the CpuState is properly initialized with all register
/// values before calling this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handler(cpu_state: *mut CpuState) {
    let ctx = runtime::get_current_context();
    let state_ref = unsafe { &mut *cpu_state };
    (ctx.syscall_handler)(state_ref, 0);
}

// Assembly trampolines for control flow transitions
unsafe extern "C" {
    /// Assembly trampoline that bridges between guest code and the dispatcher
    pub fn dispatcher_trampoline();

    /// Assembly wrapper for system call interception
    pub fn syscall_wrapper();

    /// Global variable holding supervisor stack top pointer
    static mut supervisor_stack_top: usize;
}

/// Initialize the supervisor stack pointer for the dispatcher
///
/// # Safety
///
/// This function must be called with:
/// - `stack_ptr`: A valid pointer to the base of an allocated supervisor stack
/// - `stack_size`: The size of the allocated stack in bytes
///
/// The stack memory must remain valid for the entire lifetime of the program,
/// as it will be used by the dispatcher assembly code. This function writes to
/// the global `supervisor_stack_top` variable which is accessed by assembly code.
pub unsafe fn init_supervisor_stack(stack_ptr: *mut u8, stack_size: usize) {
    // Calculate top of stack (stacks grow downward)
    unsafe {
        let stack_top = stack_ptr.add(stack_size) as usize;
        trace!(
            "Initializing supervisor stack: base={:p}, size=0x{:x}, top=0x{:x}",
            stack_ptr, stack_size, stack_top
        );
        supervisor_stack_top = stack_top;
        let value = std::ptr::addr_of!(supervisor_stack_top).read();
        trace!("Supervisor stack top set to: 0x{:x}", value);
    }
}

// Include the assembly dispatcher implementation
global_asm!(include_str!("dispatcher.S"));
