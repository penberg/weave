//! ARM64 low-level dispatcher
//! 
//! This module implements the low-level CPU state preservation and restoration
//! mechanisms for dynamic code dispatch and system call interception on ARM64
//! architectures. The code follows the AArch64 procedure call standard and
//! maintains full architectural state across transitions.
//!
//! # Components
//!
//! The implementation consists two components:
//! 
//! 1. **Dispatcher trampoline** - Saves state, calls dispatcher, restores state
//! 2. **System call wrapper** - Intercepts and handles system calls
//!
//! # Stack Layout
//!
//! ```text
//! Stack Layout (from SP):
//!   +0x000: x0-x1   (general purpose registers)
//!   +0x010: x2-x3
//!   +0x020: x4-x5
//!   +0x030: x6-x7
//!   +0x040: x8-x9
//!   +0x050: x10-x11
//!   +0x060: x12-x13
//!   +0x070: x14-x15
//!   +0x080: x16-x17
//!   +0x090: x18-x19
//!   +0x0a0: x20-x21
//!   +0x0b0: x22-x23
//!   +0x0c0: x24-x25
//!   +0x0d0: x26-x27
//!   +0x0e0: x28-x29
//!   +0x0f0: x30 (LR)
//!   +0x0f8: PC (placeholder)
//!   +0x100: NZCV flags
//!   +0x104: FPCR
//!   +0x108: FPSR
//!   +0x10c: padding
//!   +0x110: [NEON registers saved below]
//! ```

	.text
	.align	4

// ==================================================================
//                    DISPATCHER TRAMPOLINE
// ==================================================================

/// Entry point for dynamic code dispatch. This routine preserves the
/// complete CPU state, invokes the high-level dispatcher to determine
/// the target address, then restores state and transfers control.
///
/// # Inputs
/// - `x16`: target address for initial dispatch
///
/// # Stack Usage
/// - 0x110 bytes for general registers and status
/// - 0x200 bytes for NEON/SIMD registers
///
/// # Safety
/// This function preserves all architectural state and is safe to call
/// from any context where stack space is available.
	.global	_dispatcher_trampoline
_dispatcher_trampoline:
	// ----------------------------------------------------------
	// Step 1: Preserve general-purpose registers
	// ----------------------------------------------------------
	sub	sp, sp, #0x110			// Allocate stack frame
	
	stp	x0,  x1,  [sp, #0x00]		// Argument registers
	stp	x2,  x3,  [sp, #0x10]
	stp	x4,  x5,  [sp, #0x20]
	stp	x6,  x7,  [sp, #0x30]
	stp	x8,  x9,  [sp, #0x40]		// x8: indirect result
	stp	x10, x11, [sp, #0x50]		// Temporary registers
	stp	x12, x13, [sp, #0x60]
	stp	x14, x15, [sp, #0x70]
	stp	x16, x17, [sp, #0x80]		// x16: target address
	stp	x18, x19, [sp, #0x90]		// Platform register
	stp	x20, x21, [sp, #0xa0]		// Callee-saved
	stp	x22, x23, [sp, #0xb0]
	stp	x24, x25, [sp, #0xc0]
	stp	x26, x27, [sp, #0xd0]
	stp	x28, x29, [sp, #0xe0]		// x29: frame pointer
	str	x30,      [sp, #0xf0]		// Link register
	str	xzr,      [sp, #0xf8]		// PC placeholder

	// ----------------------------------------------------------
	// Step 2: Preserve processor status
	// ----------------------------------------------------------
	mrs	x19, nzcv			// Condition flags
	mrs	x20, fpcr			// FP control register
	mrs	x21, fpsr			// FP status register
	
	// Store status registers as 32-bit values
	str	w19, [sp, #0x100]		// NZCV flags
	str	w20, [sp, #0x104]		// FPCR
	str	w21, [sp, #0x108]		// FPSR
	str	wzr, [sp, #0x10c]		// Alignment padding

	// ----------------------------------------------------------
	// Step 3: Preserve NEON/SIMD state
	// ----------------------------------------------------------
	bl	_save_neon_regs			// Preserve q0-q31
	
	// ----------------------------------------------------------
	// Step 4: Invoke high-level dispatcher
	// ----------------------------------------------------------
	mov	x0, x16				// arg0: target address
	bl	_dispatcher			// Call C dispatcher
	mov	x16, x0				// Save new target

	// ----------------------------------------------------------
	// Step 5: Restore NEON/SIMD state
	// ----------------------------------------------------------
	bl	_restore_neon_regs		// Restore q0-q31

	// ----------------------------------------------------------
	// Step 6: Restore processor status
	// ----------------------------------------------------------
	ldr	w19, [sp, #0x100]		// Load NZCV flags
	ldr	w20, [sp, #0x104]		// Load FPCR
	ldr	w21, [sp, #0x108]		// Load FPSR
	
	msr	nzcv, x19			// Restore condition flags
	msr	fpcr, x20			// Restore FP control
	msr	fpsr, x21			// Restore FP status

	// ----------------------------------------------------------
	// Step 7: Restore general-purpose registers
	// ----------------------------------------------------------
	ldp	x0,  x1,  [sp, #0x00]		// Argument registers
	ldp	x2,  x3,  [sp, #0x10]
	ldp	x4,  x5,  [sp, #0x20]
	ldp	x6,  x7,  [sp, #0x30]
	ldp	x8,  x9,  [sp, #0x40]
	ldp	x10, x11, [sp, #0x50]
	ldp	x12, x13, [sp, #0x60]
	ldp	x14, x15, [sp, #0x70]
	// x16 contains jump target - preserve it
	ldr	x17,      [sp, #0x88]		// Restore x17 only
	ldp	x18, x19, [sp, #0x90]
	ldp	x20, x21, [sp, #0xa0]
	ldp	x22, x23, [sp, #0xb0]
	ldp	x24, x25, [sp, #0xc0]
	ldp	x26, x27, [sp, #0xd0]
	ldp	x28, x29, [sp, #0xe0]
	ldr	x30,      [sp, #0xf0]		// Link register
	
	add	sp, sp, #0x110			// Release stack frame

	// ----------------------------------------------------------
	// Step 8: Transfer control to target
	// ----------------------------------------------------------
	br	x16				// Jump to target


// ==================================================================
//                    SYSTEM CALL WRAPPER
// ==================================================================

/// Intercepts system calls, preserves machine state, and invokes the
/// high-level system call handler. This allows for system call filtering,
/// logging, or emulation.
///
/// # Inputs
/// - `x9`: svc immediate value
/// - `x8`/`x16`: system call number (platform dependent)
/// - `x0`-`x7`: system call arguments
///
/// # Stack Usage
/// Same as `dispatcher_trampoline`
	.global	_syscall_wrapper
_syscall_wrapper:
	// ----------------------------------------------------------
	// Step 1: Preserve general-purpose registers
	// ----------------------------------------------------------
	sub	sp, sp, #0x110			// Allocate stack frame
	
	// Preserve syscall arguments and all registers
	stp	x0,  x1,  [sp, #0x00]		// Syscall args 0-1
	stp	x2,  x3,  [sp, #0x10]		// Syscall args 2-3
	stp	x4,  x5,  [sp, #0x20]		// Syscall args 4-5
	stp	x6,  x7,  [sp, #0x30]		// Syscall args 6-7
	stp	x8,  x9,  [sp, #0x40]		// x8: syscall#, x9: svc_imm
	stp	x10, x11, [sp, #0x50]
	stp	x12, x13, [sp, #0x60]
	stp	x14, x15, [sp, #0x70]
	stp	x16, x17, [sp, #0x80]		// x16: Darwin syscall#
	stp	x18, x19, [sp, #0x90]
	stp	x20, x21, [sp, #0xa0]
	stp	x22, x23, [sp, #0xb0]
	stp	x24, x25, [sp, #0xc0]
	stp	x26, x27, [sp, #0xd0]
	stp	x28, x29, [sp, #0xe0]
	str	x30,      [sp, #0xf0]		// Link register
	str	xzr,      [sp, #0xf8]		// PC placeholder

	// ----------------------------------------------------------
	// Step 2: Preserve processor status
	// ----------------------------------------------------------
	mrs	x19, nzcv			// Condition flags
	mrs	x20, fpcr			// FP control register
	mrs	x21, fpsr			// FP status register
	
	str	w19, [sp, #0x100]		// NZCV flags
	str	w20, [sp, #0x104]		// FPCR
	str	w21, [sp, #0x108]		// FPSR
	str	wzr, [sp, #0x10c]		// Alignment padding

	// ----------------------------------------------------------
	// Step 3: Preserve NEON/SIMD state
	// ----------------------------------------------------------
	bl	_save_neon_regs			// Preserve q0-q31

	// ----------------------------------------------------------
	// Step 4: Invoke system call handler
	// ----------------------------------------------------------
	ldr	x1, [sp, #(512 + 0x48)]		// arg1: svc_imm (from x9)
	add	x0, sp, #512			// arg0: CPU state ptr
	bl	_syscall_handler		// Call C handler

	// ----------------------------------------------------------
	// Step 5: Restore NEON/SIMD state
	// ----------------------------------------------------------
	bl	_restore_neon_regs		// Restore q0-q31

	// ----------------------------------------------------------
	// Step 6: Restore processor status
	// ----------------------------------------------------------
	ldr	w19, [sp, #0x100]		// Load NZCV flags
	ldr	w20, [sp, #0x104]		// Load FPCR
	ldr	w21, [sp, #0x108]		// Load FPSR
	
	msr	nzcv, x19			// Restore condition flags
	msr	fpcr, x20			// Restore FP control
	msr	fpsr, x21			// Restore FP status

	// ----------------------------------------------------------
	// Step 7: Restore general-purpose registers
	// ----------------------------------------------------------
	ldp	x0,  x1,  [sp, #0x00]		// Syscall results
	ldp	x2,  x3,  [sp, #0x10]
	ldp	x4,  x5,  [sp, #0x20]
	ldp	x6,  x7,  [sp, #0x30]
	ldp	x8,  x9,  [sp, #0x40]
	ldp	x10, x11, [sp, #0x50]
	ldp	x12, x13, [sp, #0x60]
	ldp	x14, x15, [sp, #0x70]
	ldp	x16, x17, [sp, #0x80]
	ldp	x18, x19, [sp, #0x90]
	ldp	x20, x21, [sp, #0xa0]
	ldp	x22, x23, [sp, #0xb0]
	ldp	x24, x25, [sp, #0xc0]
	ldp	x26, x27, [sp, #0xd0]
	ldp	x28, x29, [sp, #0xe0]
	ldr	x30,      [sp, #0xf0]		// Link register

	// ----------------------------------------------------------
	// Step 8: Return to caller
	// ----------------------------------------------------------
	add	sp, sp, #0x110			// Release stack frame
	ret					// Return to caller


// ==================================================================
//                    NEON/SIMD STATE MANAGEMENT
// ==================================================================

/// Preserves all 32 NEON/SIMD registers (q0-q31) to the stack.
/// Each q register is 128 bits (16 bytes), requiring 512 bytes total.
///
/// # Stack Layout
/// ```text
/// SP-512: q0-q1
/// SP-480: q2-q3
/// ...
/// SP-32:  q30-q31
/// ```
///
/// # Safety
/// Caller must ensure at least 512 bytes of stack space available.
	.global	_save_neon_regs
_save_neon_regs:
	// Pre-decrement stack and save first pair
	stp	q0,  q1,  [sp, #-512]!		// SP -= 512; save q0-q1
	
	// Save remaining register pairs
	stp	q2,  q3,  [sp, #32]
	stp	q4,  q5,  [sp, #64]
	stp	q6,  q7,  [sp, #96]
	stp	q8,  q9,  [sp, #128]
	stp	q10, q11, [sp, #160]
	stp	q12, q13, [sp, #192]
	stp	q14, q15, [sp, #224]
	stp	q16, q17, [sp, #256]
	stp	q18, q19, [sp, #288]
	stp	q20, q21, [sp, #320]
	stp	q22, q23, [sp, #352]
	stp	q24, q25, [sp, #384]
	stp	q26, q27, [sp, #416]
	stp	q28, q29, [sp, #448]
	stp	q30, q31, [sp, #480]
	
	ret


/// Restores all 32 NEON/SIMD registers (q0-q31) from the stack.
/// Must be called after `_save_neon_regs` with stack in same state.
///
/// # Safety
/// Stack must contain valid NEON register data saved by `_save_neon_regs`.
	.global	_restore_neon_regs
_restore_neon_regs:
	// Restore register pairs in order
	ldp	q2,  q3,  [sp, #32]
	ldp	q4,  q5,  [sp, #64]
	ldp	q6,  q7,  [sp, #96]
	ldp	q8,  q9,  [sp, #128]
	ldp	q10, q11, [sp, #160]
	ldp	q12, q13, [sp, #192]
	ldp	q14, q15, [sp, #224]
	ldp	q16, q17, [sp, #256]
	ldp	q18, q19, [sp, #288]
	ldp	q20, q21, [sp, #320]
	ldp	q22, q23, [sp, #352]
	ldp	q24, q25, [sp, #384]
	ldp	q26, q27, [sp, #416]
	ldp	q28, q29, [sp, #448]
	ldp	q30, q31, [sp, #480]
	
	// Restore first pair and adjust stack
	ldp	q0,  q1,  [sp], #512		// Restore q0-q1; SP += 512
	
	ret
