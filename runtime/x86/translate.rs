use super::{CpuState, X86_MAX_INSN_SIZE, assembler::Assembler, dispatcher};
use crate::{Error, Result};
use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction};
use tracing::trace;

/// Translate and cache a basic block
pub fn translate_block(
    ctx: &mut crate::runtime::ExecutionContext,
    start_addr: u64,
    end_addr: u64,
    returnable: bool,
) -> Result<TranslatedBlock> {
    // If block is already cached, return it
    if let Some(block) = ctx.code_cache.get(&start_addr) {
        return Ok(block.clone());
    }
    let cache_addr: *mut u8 = ctx.text_allocator.start();
    let mut block = unsafe { TranslatedBlockBuilder::new(cache_addr) };
    let mut addr = start_addr;

    loop {
        if addr >= end_addr {
            break;
        }
        if !translate_insn(ctx, &mut block, addr, end_addr, returnable)? {
            break;
        }

        // Fetch next instruction length
        let insn_len = fetch_insn_len(ctx, addr, end_addr);
        if insn_len == 0 {
            break;
        }
        addr += insn_len as u64;
    }

    let block = block.finish();
    ctx.text_allocator.reserve(block.size());
    super::flush_icache_range(cache_addr, block.size());
    ctx.code_cache.insert(start_addr, block.clone());
    trace!(
        "Guest basic block {:x} cached at {:p}",
        start_addr, cache_addr
    );
    Ok(block)
}

/// Translate a single instruction and return whether to continue translating
fn translate_insn(
    ctx: &crate::runtime::ExecutionContext,
    block: &mut TranslatedBlockBuilder,
    addr: u64,
    end_addr: u64,
    _returnable: bool,
) -> Result<bool> {
    // Read up to 15 bytes for x86 instruction
    let max_len = std::cmp::min(X86_MAX_INSN_SIZE, (end_addr - addr) as usize);
    let bytes = fetch_bytes(ctx, addr, max_len);

    if bytes.is_empty() {
        trace!("End of translatable region at 0x{:016x}", addr);
        return Ok(false);
    }

    let mut decoder = Decoder::with_ip(64, &bytes, addr, DecoderOptions::NONE);
    let insn = decoder.decode();

    if insn.is_invalid() {
        return Err(Error::InstructionDecode(format!(
            "Failed to decode instruction at 0x{:016x}",
            addr
        )));
    }

    trace!(
        "Translating instruction at guest 0x{:016x}: {} (len={})",
        addr,
        insn,
        insn.len()
    );

    // Check for control flow and syscall instructions
    match insn.code() {
        iced_x86::Code::Syscall => {
            block.emit_syscall_wrapper();
            Ok(true)
        }
        iced_x86::Code::Jmp_rel32_64 | iced_x86::Code::Jmp_rel8_64 => {
            let target = insn.near_branch64();
            block.emit_exit_stub_branch(target);
            Ok(false)
        }
        iced_x86::Code::Jmp_rm64 => {
            // Indirect jump through register or memory (e.g., jmp rax, jmp [rax])
            block.emit_exit_stub_indirect_jump(&insn);
            Ok(false)
        }
        iced_x86::Code::Call_rel32_64 => {
            let target = insn.near_branch64();
            let return_addr = addr + insn.len() as u64;
            block.emit_call_exit_stub(target, return_addr);
            Ok(false)
        }
        iced_x86::Code::Call_rm64 => {
            // Indirect call through register or memory (e.g., call rax, call [rax])
            let return_addr = addr + insn.len() as u64;
            block.emit_exit_stub_indirect_call(&insn, return_addr);
            Ok(false)
        }
        iced_x86::Code::Retnq => {
            // Always route RET through dispatcher so it can catch sentinel return addresses
            // (e.g., 0 for main() return detection)
            block.emit_ret_exit_stub();
            Ok(false)
        }
        // Conditional jumps
        code if is_conditional_jump(code) => {
            let target = insn.near_branch64();
            let fallthrough = addr + insn.len() as u64;
            let condition = get_condition_code(code);
            block.emit_exit_stub_cond_branch(condition, target, fallthrough);
            Ok(false)
        }
        _ => {
            // Check for FS segment override (TLS access)
            // Guest code uses fs:[offset] to access thread-local storage.
            // We intercept this and use our guest TLS base instead.
            if insn.segment_prefix() == iced_x86::Register::FS {
                let fs_base_addr = &raw const crate::sys::linux::kernel::GUEST_FS_BASE as u64;
                let offset = insn.memory_displacement64();

                if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // mov reg, fs:[offset] -> load from guest FS base + offset
                    let dest_reg = insn.op0_register();
                    trace!(
                        "TLS access: replacing mov {:?}, fs:[{}] with guest FS base load",
                        dest_reg, offset
                    );

                    // We need a scratch register that's not the destination
                    // Use R11 as scratch (save/restore if needed)
                    if dest_reg == iced_x86::Register::R11 {
                        // Destination is R11, use RAX as scratch (save/restore)
                        block.asm.emit_push_reg64(0); // push rax
                        block.emit_mov_reg64_imm64(iced_x86::Register::RAX, fs_base_addr);
                        block.emit_mov_reg64_from_mem(iced_x86::Register::RAX, iced_x86::Register::RAX);
                        // Now RAX = guest FS base, load [rax + offset] into r11
                        block.emit_mov_reg64_from_mem_offset(dest_reg, iced_x86::Register::RAX, offset as i32);
                        block.asm.emit_pop_reg64(0); // pop rax
                    } else {
                        block.asm.emit_push_reg64(11); // push r11
                        // Load GUEST_FS_BASE address, then load the actual FS base value
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, fs_base_addr);
                        block.emit_mov_reg64_from_mem(iced_x86::Register::R11, iced_x86::Register::R11);
                        // Now R11 = guest FS base, load [r11 + offset] into dest
                        block.emit_mov_reg64_from_mem_offset(dest_reg, iced_x86::Register::R11, offset as i32);
                        block.asm.emit_pop_reg64(11); // pop r11
                    }
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Memory
                    && insn.op1_kind() == iced_x86::OpKind::Register
                {
                    // mov fs:[offset], reg -> store to guest FS base + offset
                    let src_reg = insn.op1_register();
                    trace!(
                        "TLS store: replacing mov fs:[{}], {:?} with guest FS base store",
                        offset, src_reg
                    );

                    block.asm.emit_push_reg64(11); // push r11
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, fs_base_addr);
                    block.emit_mov_reg64_from_mem(iced_x86::Register::R11, iced_x86::Register::R11);
                    // Now R11 = guest FS base, store src to [r11 + offset]
                    block.emit_mov_mem_offset_reg64(iced_x86::Register::R11, offset as i32, src_reg);
                    block.asm.emit_pop_reg64(11); // pop r11
                } else {
                    return Err(Error::InstructionDecode(format!(
                        "Unhandled FS-prefixed instruction at 0x{:x}: {:?}",
                        addr, insn
                    )));
                }
                return Ok(true);
            }

            // Check for RIP-relative memory operands
            let has_rip_rel = (0..insn.op_count()).any(|i| {
                insn.op_kind(i) == iced_x86::OpKind::Memory
                    && insn.memory_base() == iced_x86::Register::RIP
            });

            if has_rip_rel {
                let target_addr = insn.ip_rel_memory_address();

                if insn.code().mnemonic() == iced_x86::Mnemonic::Lea {
                    // LEA: convert to MOV reg, imm64
                    let dest_reg = insn.op0_register();
                    trace!(
                        "RIP-relative LEA: Converting to MOV {:?}, 0x{:x}",
                        dest_reg, target_addr
                    );
                    block.emit_mov_reg64_imm64(dest_reg, target_addr);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative MOV load: convert to absolute addressing via r11
                    // mov reg, [rip+X] -> push r11; mov r11, addr; mov reg, [r11]; pop r11
                    let dest_reg = insn.op0_register();
                    trace!(
                        "RIP-relative MOV load: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        dest_reg, dest_reg, target_addr
                    );

                    if dest_reg == iced_x86::Register::R11 {
                        // Guest wants to load into R11 - no need to save/restore
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_mov_reg64_from_mem(
                            iced_x86::Register::R11,
                            iced_x86::Register::R11,
                        );
                    } else {
                        // Save R11, use as scratch, restore
                        block.asm.emit_push_reg64(11);
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_mov_reg64_from_mem(dest_reg, iced_x86::Register::R11);
                        block.asm.emit_pop_reg64(11);
                    }
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Memory
                    && insn.op1_kind() == iced_x86::OpKind::Register
                {
                    // RIP-relative MOV store: convert to absolute addressing via r11
                    // mov [rip+X], reg -> push r11; mov r11, addr; mov [r11], reg; pop r11
                    let src_reg = insn.op1_register();
                    trace!(
                        "RIP-relative MOV store: Converting [rip], {:?} to [r11], {:?}, target=0x{:x}",
                        src_reg, src_reg, target_addr
                    );

                    if src_reg == iced_x86::Register::R11 {
                        // Source is R11 - can't use R11 as scratch too
                        // Use RAX as scratch instead: push rax; mov rax, addr; mov [rax], r11; pop rax
                        block.asm.emit_push_reg64(0); // push rax
                        block.emit_mov_reg64_imm64(iced_x86::Register::RAX, target_addr);
                        block.emit_mov_mem_from_reg64(
                            iced_x86::Register::RAX,
                            iced_x86::Register::R11,
                        );
                        block.asm.emit_pop_reg64(0); // pop rax
                    } else {
                        block.asm.emit_push_reg64(11);
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_mov_mem_from_reg64(iced_x86::Register::R11, src_reg);
                        block.asm.emit_pop_reg64(11);
                    }
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Memory
                    && insn.op1_kind() == iced_x86::OpKind::Immediate32
                {
                    // RIP-relative MOV store immediate: mov dword [rip+X], imm32
                    // -> push r11; mov r11, addr; mov dword [r11], imm32; pop r11
                    let imm = insn.immediate32();
                    trace!(
                        "RIP-relative MOV store imm32: Converting [rip], 0x{:x} to [r11], 0x{:x}, target=0x{:x}",
                        imm, imm, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.asm.emit_mov_mem_imm32(11, imm);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Mov
                    && insn.op0_kind() == iced_x86::OpKind::Memory
                    && insn.op1_kind() == iced_x86::OpKind::Immediate32to64
                {
                    // RIP-relative MOV store immediate: mov qword [rip+X], sign-extended imm32
                    // -> push r11; mov r11, addr; mov qword [r11], imm32; pop r11
                    let imm = insn.immediate32to64() as i32;
                    trace!(
                        "RIP-relative MOV store imm32to64: Converting [rip], {} to [r11], {}, target=0x{:x}",
                        imm, imm, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.asm.emit_mov_mem64_imm32(11, imm);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Add
                    && insn.op0_kind() == iced_x86::OpKind::Memory
                    && insn.op1_kind() == iced_x86::OpKind::Immediate8to32
                {
                    // RIP-relative ADD mem, imm8: add dword [rip+X], imm8
                    // -> push r11; mov r11, addr; add dword [r11], imm8; pop r11
                    let imm = insn.immediate8to32() as i8;
                    trace!(
                        "RIP-relative ADD mem imm8: Converting [rip], {} to [r11], {}, target=0x{:x}",
                        imm, imm, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.asm.emit_add_mem_imm8(11, imm);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Movsd
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative movsd: convert to absolute addressing via r11 (scratch register)
                    // movsd xmm, [rip+X] -> mov r11, addr; movsd xmm, [r11]
                    let xmm_reg = insn.op0_register();
                    trace!(
                        "RIP-relative movsd: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        xmm_reg, xmm_reg, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_movsd_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Movss
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative movss: convert to absolute addressing via r11 (scratch register)
                    // movss xmm, [rip+X] -> mov r11, addr; movss xmm, [r11]
                    let xmm_reg = insn.op0_register();
                    trace!(
                        "RIP-relative movss: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        xmm_reg, xmm_reg, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_movss_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Comisd
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative comisd: convert to absolute addressing via r11 (scratch register)
                    // comisd xmm, [rip+X] -> mov r11, addr; comisd xmm, [r11]
                    let xmm_reg = insn.op0_register();
                    trace!(
                        "RIP-relative comisd: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        xmm_reg, xmm_reg, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_comisd_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Movdqa
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative movdqa: convert to absolute addressing via r11 (scratch register)
                    // movdqa xmm, [rip+X] -> mov r11, addr; movdqa xmm, [r11]
                    let xmm_reg = insn.op0_register();
                    trace!(
                        "RIP-relative movdqa: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        xmm_reg, xmm_reg, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_movdqa_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                    block.asm.emit_pop_reg64(11);
                } else if insn.code().mnemonic() == iced_x86::Mnemonic::Movaps
                    && insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // RIP-relative movaps: convert to absolute addressing via r11
                    let xmm_reg = insn.op0_register();
                    trace!(
                        "RIP-relative movaps: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                        xmm_reg, xmm_reg, target_addr
                    );

                    block.asm.emit_push_reg64(11);
                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_movaps_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                    block.asm.emit_pop_reg64(11);
                } else if insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Memory
                {
                    // Handle other RIP-relative SSE/SSE2 instructions
                    // Try 66 prefix instructions (packed integer and packed double)
                    let opcode2_66 = match insn.code().mnemonic() {
                        // Packed integer operations
                        iced_x86::Mnemonic::Paddd => Some(0xFE),
                        iced_x86::Mnemonic::Psubd => Some(0xFA),
                        iced_x86::Mnemonic::Pxor => Some(0xEF),
                        iced_x86::Mnemonic::Por => Some(0xEB),
                        iced_x86::Mnemonic::Pand => Some(0xDB),
                        iced_x86::Mnemonic::Pandn => Some(0xDF),
                        iced_x86::Mnemonic::Pcmpeqd => Some(0x76),
                        iced_x86::Mnemonic::Pcmpgtd => Some(0x66),
                        // Packed double operations
                        iced_x86::Mnemonic::Addpd => Some(0x58),
                        iced_x86::Mnemonic::Subpd => Some(0x5C),
                        iced_x86::Mnemonic::Mulpd => Some(0x59),
                        iced_x86::Mnemonic::Divpd => Some(0x5E),
                        iced_x86::Mnemonic::Andpd => Some(0x54),
                        iced_x86::Mnemonic::Andnpd => Some(0x55),
                        iced_x86::Mnemonic::Orpd => Some(0x56),
                        iced_x86::Mnemonic::Xorpd => Some(0x57),
                        iced_x86::Mnemonic::Maxpd => Some(0x5F),
                        iced_x86::Mnemonic::Minpd => Some(0x5D),
                        iced_x86::Mnemonic::Sqrtpd => Some(0x51),
                        _ => None,
                    };

                    // Try F2 prefix instructions (scalar double)
                    let opcode2_f2 = match insn.code().mnemonic() {
                        iced_x86::Mnemonic::Addsd => Some(0x58),
                        iced_x86::Mnemonic::Subsd => Some(0x5C),
                        iced_x86::Mnemonic::Mulsd => Some(0x59),
                        iced_x86::Mnemonic::Divsd => Some(0x5E),
                        iced_x86::Mnemonic::Sqrtsd => Some(0x51),
                        iced_x86::Mnemonic::Maxsd => Some(0x5F),
                        iced_x86::Mnemonic::Minsd => Some(0x5D),
                        _ => None,
                    };

                    // Try F3 prefix instructions (scalar single)
                    let opcode2_f3 = match insn.code().mnemonic() {
                        iced_x86::Mnemonic::Addss => Some(0x58),
                        iced_x86::Mnemonic::Subss => Some(0x5C),
                        iced_x86::Mnemonic::Mulss => Some(0x59),
                        iced_x86::Mnemonic::Divss => Some(0x5E),
                        iced_x86::Mnemonic::Sqrtss => Some(0x51),
                        iced_x86::Mnemonic::Maxss => Some(0x5F),
                        iced_x86::Mnemonic::Minss => Some(0x5D),
                        _ => None,
                    };

                    let xmm_reg = insn.op0_register();

                    if let Some(op2) = opcode2_66 {
                        trace!(
                            "RIP-relative SSE2 (66) {:?}: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                            insn.code().mnemonic(),
                            xmm_reg,
                            xmm_reg,
                            target_addr
                        );

                        block.asm.emit_push_reg64(11);
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_sse2_66_xmm_from_reg(op2, xmm_reg, iced_x86::Register::R11);
                        block.asm.emit_pop_reg64(11);
                    } else if let Some(op2) = opcode2_f2 {
                        trace!(
                            "RIP-relative SSE2 (F2) {:?}: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                            insn.code().mnemonic(),
                            xmm_reg,
                            xmm_reg,
                            target_addr
                        );

                        block.asm.emit_push_reg64(11);
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_sse2_f2_xmm_from_reg(op2, xmm_reg, iced_x86::Register::R11);
                        block.asm.emit_pop_reg64(11);
                    } else if let Some(op2) = opcode2_f3 {
                        trace!(
                            "RIP-relative SSE (F3) {:?}: Converting {:?}, [rip] to {:?}, [r11], target=0x{:x}",
                            insn.code().mnemonic(),
                            xmm_reg,
                            xmm_reg,
                            target_addr
                        );

                        block.asm.emit_push_reg64(11);
                        block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                        block.emit_sse_f3_xmm_from_reg(op2, xmm_reg, iced_x86::Register::R11);
                        block.asm.emit_pop_reg64(11);
                    } else {
                        // Generic fallback: re-encode instruction with [r11] instead of [rip+disp]
                        emit_generic_rip_relative(block, &insn, target_addr, addr)?;
                    }
                } else {
                    // Generic fallback: re-encode instruction with [r11] instead of [rip+disp]
                    emit_generic_rip_relative(block, &insn, target_addr, addr)?;
                }
            } else {
                // Copy instruction as-is for identity translation
                block.emit_bytes(&bytes[0..insn.len()]);
            }
            Ok(true)
        }
    }
}

/// Generic fallback for RIP-relative instructions: re-encode the instruction
/// using [r11] as the base register instead of [rip+disp].
/// Emits: push r11; mov r11, target_addr; <re-encoded insn with [r11]>; pop r11
fn emit_generic_rip_relative(
    block: &mut TranslatedBlockBuilder,
    insn: &Instruction,
    target_addr: u64,
    addr: u64,
) -> Result<()> {
    trace!(
        "RIP-relative generic fallback at 0x{:x}: {:?}",
        addr,
        insn.code().mnemonic()
    );

    // Create a copy of the instruction with [r11] base instead of [rip+disp]
    let mut new_insn = *insn;
    // Find which operand is the memory operand and patch it
    for i in 0..new_insn.op_count() {
        if new_insn.op_kind(i) == iced_x86::OpKind::Memory
            && new_insn.memory_base() == iced_x86::Register::RIP
        {
            new_insn.set_memory_base(iced_x86::Register::R11);
            new_insn.set_memory_displacement64(0);
            new_insn.set_memory_displ_size(0);
            break;
        }
    }

    // Encode the modified instruction
    let mut encoder = Encoder::new(64);
    match encoder.encode(&new_insn, 0) {
        Ok(_) => {
            let encoded = encoder.take_buffer();
            block.asm.emit_push_reg64(11);
            block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
            block.emit_bytes(&encoded);
            block.asm.emit_pop_reg64(11);
            Ok(())
        }
        Err(e) => Err(Error::InstructionDecode(format!(
            "Failed to re-encode RIP-relative instruction at 0x{:x}: {}",
            addr, e
        ))),
    }
}

/// Convert an iced-x86 Register to a register number (0-15)
fn register_to_number(reg: iced_x86::Register) -> u8 {
    reg.number() as u8
}

fn is_conditional_jump(code: iced_x86::Code) -> bool {
    matches!(
        code,
        iced_x86::Code::Jo_rel32_64
            | iced_x86::Code::Jno_rel32_64
            | iced_x86::Code::Jb_rel32_64
            | iced_x86::Code::Jae_rel32_64
            | iced_x86::Code::Je_rel32_64
            | iced_x86::Code::Jne_rel32_64
            | iced_x86::Code::Jbe_rel32_64
            | iced_x86::Code::Ja_rel32_64
            | iced_x86::Code::Js_rel32_64
            | iced_x86::Code::Jns_rel32_64
            | iced_x86::Code::Jp_rel32_64
            | iced_x86::Code::Jnp_rel32_64
            | iced_x86::Code::Jl_rel32_64
            | iced_x86::Code::Jge_rel32_64
            | iced_x86::Code::Jle_rel32_64
            | iced_x86::Code::Jg_rel32_64
            | iced_x86::Code::Jo_rel8_64
            | iced_x86::Code::Jno_rel8_64
            | iced_x86::Code::Jb_rel8_64
            | iced_x86::Code::Jae_rel8_64
            | iced_x86::Code::Je_rel8_64
            | iced_x86::Code::Jne_rel8_64
            | iced_x86::Code::Jbe_rel8_64
            | iced_x86::Code::Ja_rel8_64
            | iced_x86::Code::Js_rel8_64
            | iced_x86::Code::Jns_rel8_64
            | iced_x86::Code::Jp_rel8_64
            | iced_x86::Code::Jnp_rel8_64
            | iced_x86::Code::Jl_rel8_64
            | iced_x86::Code::Jge_rel8_64
            | iced_x86::Code::Jle_rel8_64
            | iced_x86::Code::Jg_rel8_64
    )
}

fn get_condition_code(code: iced_x86::Code) -> u8 {
    match code {
        iced_x86::Code::Jo_rel32_64 | iced_x86::Code::Jo_rel8_64 => 0x0, // O
        iced_x86::Code::Jno_rel32_64 | iced_x86::Code::Jno_rel8_64 => 0x1, // NO
        iced_x86::Code::Jb_rel32_64 | iced_x86::Code::Jb_rel8_64 => 0x2, // B/C/NAE
        iced_x86::Code::Jae_rel32_64 | iced_x86::Code::Jae_rel8_64 => 0x3, // AE/NB/NC
        iced_x86::Code::Je_rel32_64 | iced_x86::Code::Je_rel8_64 => 0x4, // E/Z
        iced_x86::Code::Jne_rel32_64 | iced_x86::Code::Jne_rel8_64 => 0x5, // NE/NZ
        iced_x86::Code::Jbe_rel32_64 | iced_x86::Code::Jbe_rel8_64 => 0x6, // BE/NA
        iced_x86::Code::Ja_rel32_64 | iced_x86::Code::Ja_rel8_64 => 0x7, // A/NBE
        iced_x86::Code::Js_rel32_64 | iced_x86::Code::Js_rel8_64 => 0x8, // S
        iced_x86::Code::Jns_rel32_64 | iced_x86::Code::Jns_rel8_64 => 0x9, // NS
        iced_x86::Code::Jp_rel32_64 | iced_x86::Code::Jp_rel8_64 => 0xa, // P/PE
        iced_x86::Code::Jnp_rel32_64 | iced_x86::Code::Jnp_rel8_64 => 0xb, // NP/PO
        iced_x86::Code::Jl_rel32_64 | iced_x86::Code::Jl_rel8_64 => 0xc, // L/NGE
        iced_x86::Code::Jge_rel32_64 | iced_x86::Code::Jge_rel8_64 => 0xd, // GE/NL
        iced_x86::Code::Jle_rel32_64 | iced_x86::Code::Jle_rel8_64 => 0xe, // LE/NG
        iced_x86::Code::Jg_rel32_64 | iced_x86::Code::Jg_rel8_64 => 0xf, // G/NLE
        _ => panic!("Not a conditional jump"),
    }
}

fn fetch_bytes(ctx: &crate::runtime::ExecutionContext, addr: u64, len: usize) -> Vec<u8> {
    if addr >= ctx.text_start && addr < ctx.text_end {
        let available = (ctx.text_end - addr) as usize;
        let to_read = std::cmp::min(len, available);
        let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, to_read) };
        slice.to_vec()
    } else {
        vec![]
    }
}

fn fetch_insn_len(ctx: &crate::runtime::ExecutionContext, addr: u64, end_addr: u64) -> usize {
    let max_len = std::cmp::min(X86_MAX_INSN_SIZE, (end_addr - addr) as usize);
    let bytes = fetch_bytes(ctx, addr, max_len);
    if bytes.is_empty() {
        return 0;
    }

    let mut decoder = Decoder::with_ip(64, &bytes, addr, DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() { 0 } else { insn.len() }
}

pub struct TranslatedBlockBuilder {
    text_start: *mut u8,
    asm: Assembler,
}

impl TranslatedBlockBuilder {
    /// Create a new translated block builder
    ///
    /// # Safety
    ///
    /// `text_start` must be a valid pointer to a writable memory region
    pub unsafe fn new(text_start: *mut u8) -> Self {
        // Skip first 8 bytes for supervisor state storage
        let asm = unsafe { Assembler::new(text_start.add(8)) };
        Self { text_start, asm }
    }

    pub fn emit_bytes(&mut self, bytes: &[u8]) {
        self.asm.emit_bytes(bytes);
    }

    /// Emit MOV reg, imm64 instruction
    pub fn emit_mov_reg64_imm64(&mut self, reg: iced_x86::Register, imm: u64) {
        let reg_num = register_to_number(reg);
        self.asm.emit_mov_imm64(reg_num, imm);
    }

    /// Emit MOV reg, [base_reg] instruction
    pub fn emit_mov_reg64_from_mem(
        &mut self,
        dst: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let dst_num = register_to_number(dst);
        let base_num = register_to_number(base_reg);
        self.asm.emit_mov_reg64_from_mem(dst_num, base_num);
    }

    /// Emit MOV [base_reg], src instruction
    pub fn emit_mov_mem_from_reg64(
        &mut self,
        base_reg: iced_x86::Register,
        src: iced_x86::Register,
    ) {
        let base_num = register_to_number(base_reg);
        let src_num = register_to_number(src);
        self.asm.emit_mov_mem_from_reg64(base_num, src_num);
    }

    /// Emit MOV reg, [base_reg + offset] instruction
    pub fn emit_mov_reg64_from_mem_offset(
        &mut self,
        dst: iced_x86::Register,
        base_reg: iced_x86::Register,
        offset: i32,
    ) {
        let dst_num = register_to_number(dst);
        let base_num = register_to_number(base_reg);
        self.asm.emit_mov_reg64_from_mem_offset(dst_num, base_num, offset);
    }

    /// Emit MOV [base_reg + offset], src instruction
    pub fn emit_mov_mem_offset_reg64(
        &mut self,
        base_reg: iced_x86::Register,
        offset: i32,
        src: iced_x86::Register,
    ) {
        let base_num = register_to_number(base_reg);
        let src_num = register_to_number(src);
        self.asm.emit_mov_mem_offset_from_reg64(base_num, offset, src_num);
    }

    /// Emit MOVSD xmm, [reg] instruction
    pub fn emit_movsd_xmm_from_reg(
        &mut self,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm.emit_movsd_xmm_from_reg(xmm_num, base_num);
    }

    /// Emit MOVSS xmm, [reg] instruction
    pub fn emit_movss_xmm_from_reg(
        &mut self,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm.emit_movss_xmm_from_reg(xmm_num, base_num);
    }

    /// Emit COMISD xmm, [reg] instruction
    pub fn emit_comisd_xmm_from_reg(
        &mut self,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm.emit_comisd_xmm_from_reg(xmm_num, base_num);
    }

    /// Emit MOVDQA xmm, [reg] instruction
    pub fn emit_movdqa_xmm_from_reg(
        &mut self,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm.emit_movdqa_xmm_from_reg(xmm_num, base_num);
    }

    /// Emit MOVAPS xmm, [reg] instruction
    pub fn emit_movaps_xmm_from_reg(
        &mut self,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm.emit_movaps_xmm_from_reg(xmm_num, base_num);
    }

    /// Emit generic SSE2 instruction with 66 prefix: xmm, [reg]
    pub fn emit_sse2_66_xmm_from_reg(
        &mut self,
        opcode2: u8,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm
            .emit_sse2_66_xmm_from_reg(opcode2, xmm_num, base_num);
    }

    /// Emit generic SSE2 instruction with F2 prefix: xmm, [reg]
    pub fn emit_sse2_f2_xmm_from_reg(
        &mut self,
        opcode2: u8,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm
            .emit_sse2_f2_xmm_from_reg(opcode2, xmm_num, base_num);
    }

    /// Emit generic SSE instruction with F3 prefix: xmm, [reg]
    pub fn emit_sse_f3_xmm_from_reg(
        &mut self,
        opcode2: u8,
        xmm_reg: iced_x86::Register,
        base_reg: iced_x86::Register,
    ) {
        let xmm_num = register_to_number(xmm_reg);
        let base_num = register_to_number(base_reg);
        self.asm
            .emit_sse_f3_xmm_from_reg(opcode2, xmm_num, base_num);
    }

    /// Generate syscall handling wrapper
    pub fn emit_syscall_wrapper(&mut self) {
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_call_rel32(wrapper_addr);
    }

    pub fn emit_exit_stub_branch(&mut self, target_address: u64) {
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;

        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);
        // MOV R10, target_address (dispatch register)
        self.asm.emit_mov_imm64(10, target_address);
        // JMP to dispatcher
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_call_exit_stub(&mut self, target_address: u64, return_address: u64) {
        // For calls, we need to:
        // 1. Push return address onto guest stack without clobbering guest registers
        // 2. Save guest's R10, then load target address into R10 for dispatcher
        // 3. Jump to dispatcher (which will switch to host stack)

        // Push return address using sub+mov to avoid clobbering any register
        // SUB RSP, 8
        self.asm.emit_bytes(&[0x48, 0x83, 0xec, 0x08]);
        // MOV DWORD PTR [RSP], low32 of return_address
        self.asm.emit_bytes(&[0xc7, 0x04, 0x24]);
        self.asm.emit_u32(return_address as u32);
        // MOV DWORD PTR [RSP+4], high32 of return_address
        self.asm.emit_bytes(&[0xc7, 0x44, 0x24, 0x04]);
        self.asm.emit_u32((return_address >> 32) as u32);

        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);
        // MOV R10, target_address (dispatch register)
        self.asm.emit_mov_imm64(10, target_address);

        // JMP to dispatcher
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_ret_exit_stub(&mut self) {
        // For returns, we need to:
        // 1. Swap guest's R10 with return address on stack
        // 2. Jump to dispatcher
        //
        // Original stack: [..., return_addr] <- RSP
        // After XCHG: stack [..., saved_R10] <- RSP, R10 = return_addr (dispatch target)
        // After dispatcher pops R10: R10 = saved_R10 (restored), stack [...] (clean!)
        //
        // This way the RET properly "consumes" the return address from the stack.

        // XCHG R10, [RSP] - swap guest's R10 with return address
        // Encoding: REX.WR (0x4C) + 0x87 + ModR/M (0x14) + SIB (0x24)
        self.asm.emit_bytes(&[0x4c, 0x87, 0x14, 0x24]); // xchg r10, [rsp]

        // JMP to dispatcher
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_exit_stub_cond_branch(
        &mut self,
        condition: u8,
        target_address: u64,
        fallthrough_address: u64,
    ) {
        // We need to emit a conditional jump that skips over the fallthrough path
        // Layout:
        //   Jcc <skip_fallthrough>    ; conditional jump (if condition true, skip fallthrough)
        //   <fallthrough path>         ; MOV RDI + JMP dispatcher
        //   <taken path>               ; MOV RDI + JMP dispatcher

        // To avoid patching, we emit the fallthrough path into a temporary buffer
        // to measure its size, then emit the conditional jump with the correct offset

        // Save current position
        let jcc_addr = self.asm.addr();
        let size_before_jcc = self.asm.size();

        // Emit a placeholder conditional jump (we'll fix it up)
        // For now, just jump to the current address (0 offset)
        self.asm.emit_jcc_rel32(condition, jcc_addr + 6);
        let jcc_size = self.asm.size() - size_before_jcc; // Should be 6

        // Emit fallthrough path
        let fallthrough_start_size = self.asm.size();
        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);
        self.asm.emit_mov_imm64(10, fallthrough_address); // R10 = register 10
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);
        let fallthrough_size = self.asm.size() - fallthrough_start_size;

        // Now we know the actual size of the fallthrough path
        // Fix up the conditional jump to skip over it
        let taken_addr = jcc_addr + jcc_size as u64 + fallthrough_size as u64;
        let jcc_end = jcc_addr + jcc_size as u64;
        let offset = (taken_addr as i64) - (jcc_end as i64);

        // Patch the offset in the Jcc instruction (last 4 bytes)
        unsafe {
            let offset_ptr = (jcc_addr as *mut u8).add(jcc_size - 4) as *mut i32;
            std::ptr::write(offset_ptr, offset as i32);
        }

        // Emit taken path
        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);
        self.asm.emit_mov_imm64(10, target_address); // R10 = register 10
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_exit_stub_indirect_jump(&mut self, insn: &iced_x86::Instruction) {
        // For indirect jumps, we need to:
        // 1. Save guest's R10 to guest stack
        // 2. Load the target address into R10
        // 3. Jump to dispatcher

        use iced_x86::OpKind;

        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);

        match insn.op0_kind() {
            OpKind::Register => {
                // JMP reg (e.g., jmp rax)
                let reg = insn.op0_register();
                let reg_num = register_to_number(reg);

                // Move target to R10 (dispatch register)
                if reg_num != 10 {
                    self.asm.emit_mov_reg_to_reg(10, reg_num); // MOV R10, reg
                }
                // If reg_num == 10, R10 already has the target (but we just pushed it, so we need to reload)
                // Actually if it's R10, we need to load from where we pushed it
                if reg_num == 10 {
                    // mov r10, [rsp] - reload from stack since we just pushed it
                    self.asm.emit_bytes(&[0x4c, 0x8b, 0x14, 0x24]); // mov r10, [rsp]
                }

                // Jump to dispatcher
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            OpKind::Memory => {
                // JMP [mem] (e.g., jmp qword ptr [rax], jmp qword ptr [rip+offset])
                // Load the target address from memory into R10 directly
                self.asm.emit_mov_indirect_to_reg64(10, insn);

                // Jump to dispatcher - it will handle supervisor code and return address translation
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            _ => {
                // Unsupported operand kind, fall back to identity translation
                // This shouldn't happen for valid x86-64 code
                panic!(
                    "Unsupported operand kind for indirect jump: {:?}",
                    insn.op0_kind()
                );
            }
        }
    }

    pub fn emit_exit_stub_indirect_call(
        &mut self,
        insn: &iced_x86::Instruction,
        return_address: u64,
    ) {
        // For indirect calls, we need to:
        // 1. Push return address onto guest stack
        // 2. Save guest's R10 to guest stack
        // 3. Load the target address into R10 (dispatch register)
        // 4. Jump to dispatcher

        use iced_x86::OpKind;

        // Push return address onto guest stack without clobbering any register
        // SUB RSP, 8
        self.asm.emit_bytes(&[0x48, 0x83, 0xec, 0x08]);
        // MOV DWORD PTR [RSP], low32 of return_address
        self.asm.emit_bytes(&[0xc7, 0x04, 0x24]);
        self.asm.emit_u32(return_address as u32);
        // MOV DWORD PTR [RSP+4], high32 of return_address
        self.asm.emit_bytes(&[0xc7, 0x44, 0x24, 0x04]);
        self.asm.emit_u32((return_address >> 32) as u32);

        // PUSH R10 (save guest's R10 value to guest stack)
        self.asm.emit_push_reg64(10);

        match insn.op0_kind() {
            OpKind::Register => {
                // CALL reg (e.g., call rax)
                let reg = insn.op0_register();
                let reg_num = register_to_number(reg);

                // Move target to R10 (dispatch register)
                if reg_num != 10 {
                    self.asm.emit_mov_reg_to_reg(10, reg_num); // MOV R10, reg
                } else {
                    // If target is R10, reload from where we pushed it
                    // mov r10, [rsp] - reload from stack since we just pushed it
                    self.asm.emit_bytes(&[0x4c, 0x8b, 0x14, 0x24]); // mov r10, [rsp]
                }

                // Jump to dispatcher
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            OpKind::Memory => {
                // CALL [mem] (e.g., call qword ptr [rax], call qword ptr [rip+offset])
                // Load directly into R10
                self.asm.emit_mov_indirect_to_reg64(10, insn);

                // Jump to dispatcher
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            _ => {
                // Unsupported operand kind
                panic!(
                    "Unsupported operand kind for indirect call: {:?}",
                    insn.op0_kind()
                );
            }
        }
    }

    pub fn finish(self) -> TranslatedBlock {
        TranslatedBlock {
            text_start: self.text_start,
            text_size: self.asm.size() + 8,
        }
    }
}

/// Represents a translated basic block
#[derive(Debug, Clone)]
pub struct TranslatedBlock {
    text_start: *mut u8,
    text_size: usize,
}

impl TranslatedBlock {
    pub fn text_start(&self) -> *mut u8 {
        self.text_start
    }

    pub fn print_code(&self) {
        use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

        println!(
            "Translated block at {:p} ({} bytes)",
            self.text_start, self.text_size
        );

        // Skip first 8 bytes (supervisor state) and decode the actual instructions
        let code_start = unsafe { self.text_start.add(8) };
        let code_size = self.text_size - 8;
        let bytes = unsafe { std::slice::from_raw_parts(code_start, code_size) };

        let mut decoder = Decoder::with_ip(64, bytes, code_start as u64, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();

        let mut output = String::new();
        let mut instruction = iced_x86::Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            output.clear();
            formatter.format(&instruction, &mut output);
            println!("  {:016x}: {}", instruction.ip(), output);
        }
    }

    pub fn size(&self) -> usize {
        self.text_size
    }

    pub fn execute_returnable(&self, state: &mut CpuState) -> ! {
        unsafe {
            // Store cpu_state pointer at the beginning
            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            // Jump to translated guest code
            // Execution never returns here - the dispatcher handles control flow
            // and eventually calls process::exit() when the program terminates.
            let guest_code_start = self.text_start.add(8);

            // Set up initial guest registers from state
            let rdi = state.regs[super::REG_RDI];
            let rsi = state.regs[super::REG_RSI];
            let rdx = state.regs[super::REG_RDX];
            let rcx = state.regs[super::REG_RCX];
            let r8 = state.regs[super::REG_R8];
            let r9 = state.regs[super::REG_R9];
            let rsp = state.regs[super::REG_RSP];
            let rbp = state.regs[super::REG_RBP];

            tracing::debug!(
                "execute_returnable: rdi=0x{:x}, rsi=0x{:x}, rdx=0x{:x}, rsp=0x{:x}, code={:p}",
                rdi,
                rsi,
                rdx,
                rsp,
                guest_code_start
            );

            // Set up guest registers and jump to translated code
            // This never returns - the guest code will eventually call exit() or
            // main() will return (triggering the sentinel detection in the dispatcher).
            std::arch::asm!(
                "mov rsp, {rsp}",
                "mov rbp, {rbp}",
                "mov rdi, {rdi}",
                "mov rsi, {rsi}",
                "mov rdx, {rdx}",
                "mov rcx, {rcx}",
                "mov r8, {r8}",
                "mov r9, {r9}",
                "jmp {code}",
                rsp = in(reg) rsp,
                rbp = in(reg) rbp,
                rdi = in(reg) rdi,
                rsi = in(reg) rsi,
                rdx = in(reg) rdx,
                rcx = in(reg) rcx,
                r8 = in(reg) r8,
                r9 = in(reg) r9,
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }

    pub fn execute_direct(&self, state: &mut CpuState) -> ! {
        unsafe {
            // Store cpu_state pointer
            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            // Jump to translated guest code with guest stack
            let guest_code_start = self.text_start.add(8);

            // Set up initial guest registers from state
            let rdi = state.regs[super::REG_RDI];
            let rsi = state.regs[super::REG_RSI];
            let rdx = state.regs[super::REG_RDX];
            let rcx = state.regs[super::REG_RCX];
            let r8 = state.regs[super::REG_R8];
            let r9 = state.regs[super::REG_R9];
            let rsp = state.regs[super::REG_RSP];
            let rbp = state.regs[super::REG_RBP];

            tracing::debug!(
                "execute_direct: rdi=0x{:x}, rsi=0x{:x}, rdx=0x{:x}, rsp=0x{:x}, code={:p}",
                rdi,
                rsi,
                rdx,
                rsp,
                guest_code_start
            );

            // Set up guest registers and jump to translated code
            std::arch::asm!(
                "mov rsp, {rsp}",
                "mov rbp, {rbp}",
                "mov rdi, {rdi}",
                "mov rsi, {rsi}",
                "mov rdx, {rdx}",
                "mov rcx, {rcx}",
                "mov r8, {r8}",
                "mov r9, {r9}",
                "jmp {code}",
                rsp = in(reg) rsp,
                rbp = in(reg) rbp,
                rdi = in(reg) rdi,
                rsi = in(reg) rsi,
                rdx = in(reg) rdx,
                rcx = in(reg) rcx,
                r8 = in(reg) r8,
                r9 = in(reg) r9,
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }
}
