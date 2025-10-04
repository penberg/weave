//! x86-64 low-level dispatcher
//!
//! This module implements the low-level CPU state preservation and restoration
//! mechanisms for dynamic code dispatch and system call interception on x86-64.
//!
//! # Stack Layout
//!
//! Stack Layout (from RSP):
//!   +0x00: RAX
//!   +0x08: RCX
//!   +0x10: RDX
//!   +0x18: RBX
//!   +0x20: RSP (original)
//!   +0x28: RBP
//!   +0x30: RSI
//!   +0x38: RDI
//!   +0x40: R8
//!   +0x48: R9
//!   +0x50: R10
//!   +0x58: R11
//!   +0x60: R12
//!   +0x68: R13
//!   +0x70: R14
//!   +0x78: R15
//!   +0x80: RIP (return address)
//!   +0x88: RFLAGS
//!   Total: 0x90 bytes (144 bytes)

	.text
	.align	16

// ==================================================================
//                    DISPATCHER TRAMPOLINE
// ==================================================================

	.global	dispatcher_trampoline
dispatcher_trampoline:
	// Save all GPRs
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	rsp		// Will be adjusted later
	push	rbp
	push	rsi
	push	rdi		// Target address already in RDI
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	// Save RFLAGS
	pushfq

	// Call dispatcher
	// RDI already contains target address
	mov	rsi, rsp	// RSI = stack pointer (for return address access)
	call	dispatcher	// Returns new target in RAX

	// Save returned target
	mov	r15, rax	// Save new target in R15

	// Restore RFLAGS
	popfq

	// Restore GPRs (except R15 which has our target)
	add	rsp, 0x08	// Skip R15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rbp
	add	rsp, 0x08	// Skip RSP
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax

	// Jump to target (still in R15)
	jmp	r15

// ==================================================================
//                    SYSTEM CALL WRAPPER
// ==================================================================

	.global	syscall_wrapper
syscall_wrapper:
	// Save all GPRs in REVERSE order so stack layout matches CpuState struct
	// CpuState expects: regs[0]=RAX, regs[1]=RCX, ..., regs[15]=R15, rflags
	// Push in reverse: R15, R14, ..., RAX so they appear in forward order in memory
	push	r15
	push	r14
	push	r13
	push	r12
	push	r11
	push	r10
	push	r9
	push	r8
	push	rdi
	push	rsi
	push	rbp
	push	rsp		// Will be adjusted later
	push	rbx
	push	rdx
	push	rcx
	push	rax

	// Save RFLAGS
	pushfq

	// Push padding to align stack to 16 bytes before call
	sub	rsp, 8

	// Adjust saved RSP value (16 regs + rflags + padding = 18 pushes = 144 bytes)
	mov	r11, rsp
	add	r11, 144
	mov	QWORD PTR [rsp + 16 + 32], r11  // RSP is at regs[4] = offset 32 from RAX, +16 for padding+rflags

	// CpuState starts at RAX which is at rsp+16 (skip padding + RFLAGS)
	lea	rdi, [rsp + 16]
	call	syscall_handler

	// Remove padding
	add	rsp, 8

	// Restore RFLAGS
	popfq

	// Restore GPRs in reverse order (opposite of push)
	pop	rax
	pop	rcx
	pop	rdx
	pop	rbx
	add	rsp, 8		// Skip saved RSP
	pop	rbp
	pop	rsi
	pop	rdi
	pop	r8
	pop	r9
	pop	r10
	pop	r11
	pop	r12
	pop	r13
	pop	r14
	pop	r15

	// Return to caller
	ret
