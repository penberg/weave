use crate::runtime::{
    self,
    x86::{CpuState, TIME_TICK, translate::translate_block},
};
use core::arch::global_asm;
use std::sync::atomic::Ordering;
use tracing::trace;

/// Handles control flow transitions between translated code blocks
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dispatcher(target_addr: usize, _stack_ptr: *mut u8) -> usize {
    let ctx = runtime::get_current_context();

    TIME_TICK.fetch_add(1, Ordering::Release);

    let target_addr = target_addr as u64;

    let is_guest = target_addr >= ctx.text_start && target_addr < ctx.text_end;

    trace!(
        "Dispatching to 0x{:016x} ({})",
        target_addr,
        if is_guest { "guest" } else { "supervisor" }
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
        // Target address is in supervisor code
        target_addr as usize
    }
}

/// Handles system call interception from translated guest code
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handler(cpu_state: *mut CpuState) {
    let ctx = runtime::get_current_context();
    let state_ref = unsafe { &*cpu_state };
    (ctx.syscall_handler)(state_ref, 0);
}

// Assembly trampolines for control flow transitions
unsafe extern "C" {
    /// Assembly trampoline that bridges between guest code and the dispatcher
    pub fn dispatcher_trampoline();

    /// Assembly wrapper for system call interception
    pub fn syscall_wrapper();
}

// Include the assembly dispatcher implementation
global_asm!(include_str!("dispatcher.S"));
