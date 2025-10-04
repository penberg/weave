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
    arm64::{CpuState, TIME_TICK, translate::translate_block},
};
use core::arch::global_asm;
use std::sync::atomic::Ordering;
use tracing::trace;

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
/// * `target_addr` - The target address of the branch instruction
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
pub unsafe extern "C" fn dispatcher(target_addr: usize) -> usize {
    let ctx = runtime::get_current_context();

    // TODO: This will not work once we back-patch translated branches not to
    // call into the dispatcher. We need to increment time tick in the exit stubs instead.
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
        // The 8-byte offset skips the block header used by the translation system
        unsafe { block.text_start().add(8) as usize }
    } else {
        // Target address is supervisor code (e.g., GOT stubs detected at translation time).
        // Note: Prior to the simplification in commit 41425ab, this branch also handled
        // return address translation for calls from guest to supervisor. That logic was
        // removed because GOT stubs are now detected and translated at translation time,
        // eliminating the need for runtime return address patching.
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

    let state_ref = unsafe { &*cpu_state };
    let svc_imm_u16 = svc_imm as u16;

    (ctx.syscall_handler)(state_ref, svc_imm_u16);
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
