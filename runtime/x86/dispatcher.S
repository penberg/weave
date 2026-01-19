//! x86-64 low-level dispatcher
//!
//! This module implements stack switching and state preservation for dynamic
//! code dispatch following the DynamoRIO approach: separate application and
//! supervisor stacks for transparency.
//!
//! # Architecture
//!
//! - Application code runs on the application stack (inherited from OS)
//! - Dispatcher and runtime code run on a separate supervisor stack
//! - Stack switching occurs at dispatcher entry/exit
//!
//! # Calling Convention
//!
//! System V AMD64 ABI:
//! - RDI: target address (arg0)
//! - RAX: return value (translated block address)

	.text
	.align	16

// ==================================================================
//                    DISPATCHER TRAMPOLINE
// ==================================================================

/// Entry point for dynamic code dispatch. Switches from application stack
/// to supervisor stack, calls the high-level dispatcher, then switches back
/// and jumps to the translated code.
///
/// # Inputs
/// - `r10`: target address for dispatch (scratch register - doesn't clobber guest state!)
/// - `rsp`: application stack pointer
///
/// # Outputs
/// - Control transfers to translated code at address returned by dispatcher
///
/// # Preserved
/// - All application registers and flags (including RCX for computed values!)
/// - Application stack pointer
	.global	dispatcher_trampoline
dispatcher_trampoline:
	// ----------------------------------------------------------
	// Step 1: Save guest R15 and application RSP
	// ----------------------------------------------------------
	// Save guest R15 to guest stack (before we clobber any registers)
	push	r15
	// Save application RSP to global variable (avoids clobbering R15)
	mov	[rip + app_stack_save], rsp

	// ----------------------------------------------------------
	// Step 2: Get supervisor stack pointer
	// ----------------------------------------------------------
	// Load from global variable using RIP-relative addressing (PIC-safe)
	mov	rsp, qword ptr [rip + supervisor_stack_top]	// Switch to supervisor stack

	// ----------------------------------------------------------
	// Step 3: Save application state on supervisor stack
	// ----------------------------------------------------------
	// Save target address and application state
	push	r10				// Target address (from R10)
	push	qword ptr [rip + app_stack_save]	// Application RSP

	// Save callee-saved registers
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14

	// Save caller-saved registers (function arguments and volatile regs)
	push	rdi				// arg0
	push	rsi				// arg1
	push	rdx				// arg2
	push	rcx				// arg3 (now preserved since R10 is dispatch register!)
	push	r8				// arg4
	push	r9				// arg5
	push	r10				// volatile (contains target, but save anyway for consistency)
	push	r11				// volatile
	push	rax				// return value / volatile

	// Save XMM registers (floating-point return values and volatile FP regs)
	// XMM0-XMM7 are volatile (caller-saved) in System V AMD64 ABI and used
	// for FP argument passing and return values (e.g., sqrt, sin, cos).
	// XMM8-XMM15 are also volatile but not used by the dispatcher, so we
	// don't save them (they remain untouched through our code).
	// Reserve space: 8 XMM regs * 16 bytes = 128 bytes + 8 bytes padding for alignment
	sub	rsp, 136
	// Note: Use movdqu (unaligned) because stack is only 8-byte aligned here
	movdqu	[rsp + 0x00], xmm0		// FP return value
	movdqu	[rsp + 0x10], xmm1
	movdqu	[rsp + 0x20], xmm2
	movdqu	[rsp + 0x30], xmm3
	movdqu	[rsp + 0x40], xmm4
	movdqu	[rsp + 0x50], xmm5
	movdqu	[rsp + 0x60], xmm6
	movdqu	[rsp + 0x70], xmm7

	// Save flags
	pushfq

	// ----------------------------------------------------------
	// Step 4: Align stack and call dispatcher
	// ----------------------------------------------------------
	// Stack layout after all pushes (high address → low address):
	//
	// rsp+264: r10 (TARGET ADDRESS)
	// rsp+256: r15 (app RSP)
	//        --- callee-saved registers ---
	// rsp+248: rbx
	// rsp+240: rbp
	// rsp+232: r12
	// rsp+224: r13
	// rsp+216: r14
	//        --- caller-saved registers ---
	// rsp+208: rdi
	// rsp+200: rsi
	// rsp+192: rdx
	// rsp+184: rcx
	// rsp+176: r8
	// rsp+168: r9
	// rsp+160: r10 (clobbered - contains target, not app value)
	// rsp+152: r11
	// rsp+144: rax
	//        --- XMM registers (136 bytes with 8-byte padding) ---
	// rsp+8:   xmm0-xmm7 (128 bytes at offsets 0x00-0x70)
	//        --- flags ---
	// rsp+0:   rflags (8 bytes)
	//
	// Total stack usage:
	//   Initial pushes: 2 qwords (r10, r15) = 16 bytes
	//   Callee-saved:   5 qwords = 40 bytes
	//   Caller-saved:   9 qwords = 72 bytes (including rcx!)
	//   XMM space:      136 bytes (128 + 8 padding)
	//   Flags:          8 bytes
	//   Total:          272 bytes (16-byte aligned)

	mov	rdi, [rsp + 264]		// arg0: target_addr (from saved R10 in dispatch stub)
	mov	rsi, [rsp + 256]		// arg1: application RSP (from saved R15)
	mov	rdx, [rsp + 200]		// arg2: saved RSI (for debugging)
	mov	rcx, [rsp + 248]		// arg3: saved RBX (for debugging)
	mov	r8, [rsp + 208]			// arg4: saved RDI (for debugging)
	mov	r9, [rsp + 152]			// arg5: saved R11 (for debugging)

	// Stack is 16-byte aligned (272 bytes = 16 * 17)
	call	dispatcher
	// RAX now contains translated block address

	// ----------------------------------------------------------
	// Step 5: Save translated block address to global
	// ----------------------------------------------------------
	// Save to global variable so we don't need to clobber any guest register
	mov	[rip + translated_target], rax

	// ----------------------------------------------------------
	// Step 6: Restore application state
	// ----------------------------------------------------------
	// Restore flags
	popfq

	// Restore XMM registers
	movdqu	xmm0, [rsp + 0x00]
	movdqu	xmm1, [rsp + 0x10]
	movdqu	xmm2, [rsp + 0x20]
	movdqu	xmm3, [rsp + 0x30]
	movdqu	xmm4, [rsp + 0x40]
	movdqu	xmm5, [rsp + 0x50]
	movdqu	xmm6, [rsp + 0x60]
	movdqu	xmm7, [rsp + 0x70]
	add	rsp, 136			// Pop XMM space (128 + 8 padding)

	// Restore caller-saved registers
	pop	rax
	pop	r11
	add	rsp, 8				// Skip R10 - it was clobbered by dispatch stub, don't restore!
	pop	r9
	pop	r8
	pop	rcx				// Restore guest's RCX value
	pop	rdx
	pop	rsi
	pop	rdi

	// Restore callee-saved registers
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx

	// Skip application RSP and target address slots
	add	rsp, 16

	// ----------------------------------------------------------
	// Step 7: Switch back to application stack
	// ----------------------------------------------------------
	mov	rsp, [rip + app_stack_save]

	// ----------------------------------------------------------
	// Step 8: Restore guest's R15 and R10 from guest stack
	// ----------------------------------------------------------
	// The trampoline entry pushed R15, and exit stubs pushed R10 before
	// overwriting it with dispatch target. Pop both to restore guest values.
	pop	r15
	pop	r10

	// ----------------------------------------------------------
	// Step 9: Transfer control to translated code
	// ----------------------------------------------------------
	jmp	[rip + translated_target]


// ==================================================================
//                    SYSTEM CALL WRAPPER
// ==================================================================

/// Intercepts system calls, switches to supervisor stack, and invokes
/// the system call handler.
///
/// # Inputs
/// - `rax`: system call number
/// - System call arguments in standard registers
///
/// # Stack Usage
/// Allocates space for CpuState + XMM registers on supervisor stack
	.global	syscall_wrapper
syscall_wrapper:
	// ----------------------------------------------------------
	// Step 1: Save application RSP
	// ----------------------------------------------------------
	mov	[rip + app_stack_save], rsp	// Save application RSP to global

	// ----------------------------------------------------------
	// Step 2: Switch to supervisor stack
	// ----------------------------------------------------------
	// Load from global variable using RIP-relative addressing (PIC-safe)
	mov	rsp, qword ptr [rip + supervisor_stack_top]

	// ----------------------------------------------------------
	// Step 3: Save XMM registers
	// ----------------------------------------------------------
	// The syscall handler is written in Rust and may use XMM registers for:
	// - Formatting in trace!() macros
	// - Auto-vectorization
	// - Calling other Rust code
	// Reserve space: 8 XMM regs * 16 bytes = 128 bytes
	sub	rsp, 128
	movdqu	[rsp + 0x00], xmm0
	movdqu	[rsp + 0x10], xmm1
	movdqu	[rsp + 0x20], xmm2
	movdqu	[rsp + 0x30], xmm3
	movdqu	[rsp + 0x40], xmm4
	movdqu	[rsp + 0x50], xmm5
	movdqu	[rsp + 0x60], xmm6
	movdqu	[rsp + 0x70], xmm7

	// ----------------------------------------------------------
	// Step 4: Allocate CpuState on supervisor stack
	// ----------------------------------------------------------
	// CpuState layout: 16 regs (128 bytes) + rflags (8 bytes) = 136 bytes
	// Round up to 144 bytes (0x90) for alignment
	sub	rsp, 0x90

	// ----------------------------------------------------------
	// Step 5: Save all registers to CpuState
	// ----------------------------------------------------------
	mov	[rsp + 0x00], rax		// regs[0] = RAX (syscall number)
	mov	[rsp + 0x08], rcx		// regs[1] = RCX
	mov	[rsp + 0x10], rdx		// regs[2] = RDX
	mov	[rsp + 0x18], rbx		// regs[3] = RBX
	// Save application RSP from global variable
	mov	rax, [rip + app_stack_save]
	mov	[rsp + 0x20], rax		// regs[4] = RSP (application RSP)
	mov	[rsp + 0x28], rbp		// regs[5] = RBP
	mov	[rsp + 0x30], rsi		// regs[6] = RSI
	mov	[rsp + 0x38], rdi		// regs[7] = RDI
	mov	[rsp + 0x40], r8		// regs[8] = R8
	mov	[rsp + 0x48], r9		// regs[9] = R9
	mov	[rsp + 0x50], r10		// regs[10] = R10
	mov	[rsp + 0x58], r11		// regs[11] = R11
	mov	[rsp + 0x60], r12		// regs[12] = R12
	mov	[rsp + 0x68], r13		// regs[13] = R13
	mov	[rsp + 0x70], r14		// regs[14] = R14
	mov	[rsp + 0x78], r15		// regs[15] = R15 (guest R15, not clobbered)

	// Save RFLAGS
	pushfq
	pop	rax
	mov	[rsp + 0x80], rax

	// ----------------------------------------------------------
	// Step 6: Call syscall handler
	// ----------------------------------------------------------
	mov	rdi, rsp			// arg0: CpuState pointer
	and	rsp, -16			// Align stack
	call	syscall_handler

	// ----------------------------------------------------------
	// Step 7: Restore registers from CpuState
	// ----------------------------------------------------------
	// Restore RFLAGS
	mov	rax, [rsp + 0x80]
	push	rax
	popfq

	// Restore all GPRs
	mov	rax, [rsp + 0x00]		// RAX (syscall result)
	mov	rcx, [rsp + 0x08]
	mov	rdx, [rsp + 0x10]
	mov	rbx, [rsp + 0x18]
	mov	rbp, [rsp + 0x28]
	mov	rsi, [rsp + 0x30]
	mov	rdi, [rsp + 0x38]
	mov	r8,  [rsp + 0x40]
	mov	r9,  [rsp + 0x48]
	mov	r10, [rsp + 0x50]
	mov	r11, [rsp + 0x58]
	mov	r12, [rsp + 0x60]
	mov	r13, [rsp + 0x68]
	mov	r14, [rsp + 0x70]
	mov	r15, [rsp + 0x78]		// Guest R15

	// Clean up CpuState from stack
	add	rsp, 0x90

	// ----------------------------------------------------------
	// Step 8: Restore XMM registers
	// ----------------------------------------------------------
	movdqu	xmm0, [rsp + 0x00]
	movdqu	xmm1, [rsp + 0x10]
	movdqu	xmm2, [rsp + 0x20]
	movdqu	xmm3, [rsp + 0x30]
	movdqu	xmm4, [rsp + 0x40]
	movdqu	xmm5, [rsp + 0x50]
	movdqu	xmm6, [rsp + 0x60]
	movdqu	xmm7, [rsp + 0x70]
	add	rsp, 128			// Pop XMM space

	// ----------------------------------------------------------
	// Step 9: Switch back to application stack
	// ----------------------------------------------------------
	mov	rsp, [rip + app_stack_save]	// Restore application RSP

	// ----------------------------------------------------------
	// Step 10: Return to caller
	// ----------------------------------------------------------
	ret


// ==================================================================
//                    DATA SECTION
// ==================================================================

	.data
	.align	8

/// Supervisor stack top pointer (set at runtime by init function)
supervisor_stack_top:
	.quad	0

/// Saved application stack pointer (used by dispatcher trampoline)
app_stack_save:
	.quad	0

/// Translated block target address (used by dispatcher trampoline)
translated_target:
	.quad	0
