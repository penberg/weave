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
/// - `rcx`: target address for dispatch (DynamoRIO approach - doesn't conflict with args!)
/// - `rsp`: application stack pointer
///
/// # Outputs
/// - Control transfers to translated code at address returned by dispatcher
///
/// # Preserved
/// - All application registers and flags (including RDI for function arguments!)
/// - Application stack pointer
	.global	dispatcher_trampoline
dispatcher_trampoline:
	// ----------------------------------------------------------
	// Step 1: Save application RSP and callee-saved registers
	// ----------------------------------------------------------
	// We need to preserve application's callee-saved registers
	// since we're about to use them for our own purposes
	mov	r15, rsp			// R15 = application RSP

	// ----------------------------------------------------------
	// Step 2: Get supervisor stack pointer
	// ----------------------------------------------------------
	// Load from global variable using RIP-relative addressing (PIC-safe)
	mov	rsp, qword ptr [rip + supervisor_stack_top]	// Switch to supervisor stack

	// ----------------------------------------------------------
	// Step 3: Save application state on supervisor stack
	// ----------------------------------------------------------
	// Save target address and application state
	push	rcx				// Target address (from RCX)
	push	r15				// Application RSP

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
	push	r8				// arg4
	push	r9				// arg5
	push	r10				// volatile
	push	r11				// volatile
	push	rax				// return value / volatile

	// Save XMM registers (floating-point return values and volatile FP regs)
	// XMM0-XMM7 are volatile (caller-saved) in System V AMD64 ABI and used
	// for FP argument passing and return values (e.g., sqrt, sin, cos).
	// XMM8-XMM15 are also volatile but not used by the dispatcher, so we
	// don't save them (they remain untouched through our code).
	// Reserve space: 8 XMM regs * 16 bytes = 128 bytes
	sub	rsp, 128
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
	// rsp+248: rcx (TARGET ADDRESS)
	// rsp+240: r15 (app RSP)
	//        --- callee-saved registers ---
	// rsp+232: rbx
	// rsp+224: rbp
	// rsp+216: r12
	// rsp+208: r13
	// rsp+200: r14
	//        --- caller-saved registers ---
	// rsp+192: rdi
	// rsp+184: rsi
	// rsp+176: rdx
	// rsp+168: r8
	// rsp+160: r9
	// rsp+152: r10
	// rsp+144: r11
	// rsp+136: rax
	//        --- XMM registers (128 bytes) ---
	// rsp+120: xmm0 (16 bytes)
	// rsp+104: xmm1 (16 bytes)
	// rsp+88:  xmm2 (16 bytes)
	// rsp+72:  xmm3 (16 bytes)
	// rsp+56:  xmm4 (16 bytes)
	// rsp+40:  xmm5 (16 bytes)
	// rsp+24:  xmm6 (16 bytes)
	// rsp+8:   xmm7 (16 bytes)
	//        --- flags ---
	// rsp+0:   rflags (8 bytes)
	//
	// Total stack usage:
	//   Initial pushes: 2 qwords (rcx, r15) = 16 bytes
	//   Callee-saved:   5 qwords = 40 bytes
	//   Caller-saved:   8 qwords = 64 bytes
	//   XMM space:      128 bytes
	//   Flags:          8 bytes
	//   Total:          256 bytes (16-byte aligned)

	mov	rdi, [rsp + 248]		// arg0: target_addr (from saved RCX)
	mov	rsi, [rsp + 240]		// arg1: application RSP (from saved R15)

	// Stack is already 16-byte aligned (256 bytes = 16 * 16)
	call	dispatcher
	// RAX now contains translated block address

	// ----------------------------------------------------------
	// Step 5: Save translated block address temporarily
	// ----------------------------------------------------------
	// We need to save the return value (target address) from the dispatcher
	// but we can't use r11 anymore since we need to restore all registers
	// Let's use the stack slot where rcx was saved (we don't need it anymore)
	mov	[rsp + 248], rax		// Save target address in rcx's old slot

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
	add	rsp, 128			// Pop XMM space

	// Restore caller-saved registers
	pop	rax
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdx
	pop	rsi
	pop	rdi

	// Restore callee-saved registers
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx

	// Restore application RSP and get target address
	pop	r15				// r15 = application RSP
	pop	r11				// r11 = target address (from modified rcx slot)

	// ----------------------------------------------------------
	// Step 7: Switch back to application stack
	// ----------------------------------------------------------
	mov	rsp, r15			// Restore application RSP

	// ----------------------------------------------------------
	// Step 8: Transfer control to translated code
	// ----------------------------------------------------------
	jmp	r11				// Jump to translated block


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
	mov	r15, rsp			// Save application RSP

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
	mov	[rsp + 0x20], r15		// regs[4] = RSP (application RSP)
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
	mov	[rsp + 0x78], r15		// regs[15] = R15 (contains app RSP)

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
	mov	r15, [rsp + 0x78]		// Application RSP

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
	mov	rsp, r15			// Restore application RSP

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
