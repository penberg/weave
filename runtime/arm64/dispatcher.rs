//! Dynamic binary translation dispatcher module.
//!
//! This module implements the core control flow mechanism for the Weave supervisor,
//! handling transitions between translated guest code blocks and system call interception.
//!
//! # Architecture
//!
//! The dispatcher serves as the bridge between native execution of translated code
//! and the supervisor's control logic. When translated guest code reaches a control
//! flow boundary (branch or system call), execution transfers to this module through
//! assembly trampolines.
//!
//! # Safety
//!
//! This module contains unsafe code due to:
//! - Direct memory manipulation of CPU state
//! - FFI with assembly trampolines
//! - Raw pointer dereferencing for performance

use crate::runtime::{
    self,
    arm64::{CpuState, translate::translate_block},
    time,
};
use core::arch::global_asm;
use tracing::trace;

/// Sentinel address used to detect when main() returns.
/// This is an invalid address that will never be a real code address.
pub const MAIN_RETURN_SENTINEL: u64 = 0xDEAD_CAFE_0000_0000;

/// Handles control flow transitions between translated code blocks.
///
/// This function is called by the assembly exit stubs when translated guest code
/// reaches a branch instruction. It determines whether the target address requires
/// translation or can be executed directly.
///
/// # Control Flow
///
/// 1. Exit stub saves guest CPU state and calls this function with the branch target
/// 2. Function checks if target is within guest text segment:
///    - If yes: Translates the target block and returns its address
///    - If no: Returns the target address unchanged (for supervisor code)
/// 3. Assembly trampoline restores CPU state and jumps to returned address
///
/// # Arguments
///
/// * `target` - The target address of the branch instruction
///
/// # Returns
///
/// The address to jump to next:
/// - For guest code: Address of newly translated block (offset by 8 bytes)
/// - For supervisor code: Original target address
///
/// # Safety
///
/// This function is unsafe because:
/// - It dereferences raw pointers to the execution context
/// - It returns addresses that will be jumped to directly
/// - Caller must ensure the context pointer is valid
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dispatcher(target_addr: usize, stack_ptr: *mut u8) -> usize {
    let ctx = runtime::get_current_context();

    // TODO: This will not work once we back-patch translated branches not to
    // call into the dispatcher. We need to increment time tick in the exit stubs instead.
    time::tick();

    let target_addr = target_addr as u64;

    let is_guest = target_addr >= ctx.text_start && target_addr < ctx.text_end;

    // Debug: print saved registers for all calls
    let saved_x0 = unsafe { *(stack_ptr as *const u64) };
    let saved_x1 = unsafe { *(stack_ptr.add(8) as *const u64) };
    let saved_x16 = unsafe { *(stack_ptr.add(0x80) as *const u64) };
    let saved_x30 = unsafe { *(stack_ptr.add(0xf0) as *const u64) };
    trace!(
        "Dispatcher: target=0x{:x} ({}), saved x0=0x{:x}, x1=0x{:x}, x16=0x{:x}, x30=0x{:x}",
        target_addr,
        if is_guest { "guest" } else { "supervisor" },
        saved_x0,
        saved_x1,
        saved_x16,
        saved_x30
    );

    // Check if this is the main return sentinel
    if target_addr == MAIN_RETURN_SENTINEL {
        let exit_code = saved_x0 as i32;
        trace!("Main returned with exit code: {}", exit_code);
        // Exit the process with main's return value
        std::process::exit(exit_code);
    }

    if is_guest {
        ctx.state.pc = target_addr;

        let block = translate_block(ctx, target_addr, ctx.text_end, false).unwrap();

        if ctx.print_code {
            block.print_code();
        }

        // Return the address of the translated code (skip first 8 bytes)
        // The 8-byte offset skips the block header used by the translation system
        unsafe { block.text_start().add(8) as usize }
    } else {
        // Target address is in the supervisor code, but we need to translate
        // the return address if it points to guest code

        // Get the current return address from x30 saved on stack
        // x30 is saved at offset 0xf0 from stack pointer
        let return_addr_ptr = unsafe { stack_ptr.add(0xf0) as *mut u64 };
        let return_addr = unsafe { *return_addr_ptr };
        let is_return_guest = return_addr >= ctx.text_start && return_addr < ctx.text_end;

        trace!(
            "Supervisor call: return_addr=0x{:x}, text_start=0x{:x}, text_end=0x{:x}, is_return_guest={}",
            return_addr, ctx.text_start, ctx.text_end, is_return_guest
        );

        if is_return_guest {
            trace!("Translating return address block: 0x{:016x}", return_addr);
            let return_block = translate_block(ctx, return_addr, ctx.text_end, false).unwrap();

            // Update x30 on stack to point to translated return code
            let translated_return_addr = unsafe { return_block.text_start().add(8) as u64 };
            unsafe { *return_addr_ptr = translated_return_addr };
            trace!(
                "Updated x30 to translated return address: 0x{:016x}",
                translated_return_addr
            );
        }

        // Target address is in the supervisor code, execute directly.
        target_addr as usize
    }
}

/// Handles system call interception from translated guest code.
///
/// This function is called by the assembly syscall wrapper when translated guest
/// code executes a system call instruction. It provides deterministic system call
/// emulation by forwarding the call to the registered handler.
///
/// # Control Flow
///
/// 1. Guest executes system call instruction (e.g., `svc` on ARM64)
/// 2. Translated instruction calls assembly `syscall_wrapper`
/// 3. Wrapper saves CPU state and calls this function
/// 4. Function forwards to the context's registered syscall handler
/// 5. Handler emulates the system call deterministically
/// 6. Control returns through the assembly wrapper to guest code
///
/// # Arguments
///
/// * `cpu_state` - Pointer to the saved CPU state of the guest
/// * `svc_imm` - The immediate value from the system call instruction
///
/// # Safety
///
/// This function is unsafe because:
/// - It dereferences raw pointers to CPU state and execution context
/// - The caller must ensure both pointers are valid and properly aligned
/// - The syscall handler must not corrupt the CPU state
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handler(cpu_state: *mut CpuState, svc_imm: u32) {
    let ctx = runtime::get_current_context();

    trace!("syscall_handler(svc_imm: {})", svc_imm);

    let state_ref = unsafe { &mut *cpu_state };
    let svc_imm_u16 = svc_imm as u16;

    (ctx.syscall_handler)(state_ref, svc_imm_u16);
}

/// Handle BRK trap instructions
///
/// This is called when guest code executes a BRK instruction, which is used
/// for traps/assertions. On Darwin, BRK #1 is typically __builtin_trap().
#[unsafe(no_mangle)]
pub extern "C" fn brk_trap_handler(addr: u64, imm: u64) -> ! {
    eprintln!("BRK #{} trap at 0x{:016x}", imm, addr);
    std::process::abort();
}

// Assembly trampolines for control flow transitions
unsafe extern "C" {
    /// Assembly trampoline that bridges between guest code and the dispatcher.
    ///
    /// Saves guest CPU state, calls the Rust dispatcher function, then
    /// restores state and jumps to the returned address.
    pub fn dispatcher_trampoline();

    /// Assembly wrapper for system call interception.
    ///
    /// Saves guest CPU state, calls the Rust syscall handler, then
    /// restores state and returns to guest code.
    pub fn syscall_wrapper();
}

// Defines the dispatcher_trampoline() and syscall_wrapper() functions.
global_asm!(include_str!("dispatcher.S"));
