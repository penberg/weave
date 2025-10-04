use super::{ARM64_INSN_SIZE, CpuState, assembler::Assembler, dispatcher};
use crate::{Error, Result};
use disarm64::decoder;
use tracing::trace;

/// Check if addr points to start of GOT stub (adrp x16/ldr x16/br x16 pattern) and return supervisor address
fn check_got_stub_at(ctx: &crate::runtime::ExecutionContext, addr: u64) -> Option<u64> {
    let insn1 = fetch_insn(ctx, addr)?;
    let insn2 = fetch_insn(ctx, addr + 4)?;
    let insn3 = fetch_insn(ctx, addr + 8)?;

    let decoded1 = decoder::decode(insn1)?;
    let decoded2 = decoder::decode(insn2)?;
    let decoded3 = decoder::decode(insn3)?;

    // Check for adrp x16, <page>
    let page_addr =
        if let decoder::Operation::PCRELADDR(decoder::PCRELADDR::ADRP_Rd_ADDR_ADRP(adrp)) =
            decoded1.operation
        {
            if adrp.rd() != 16 {
                return None;
            }
            let imm21 = adrp.immlo() as i32 | ((adrp.immhi() as i32) << 2);
            let signed_offset = if imm21 & 0x100000 != 0 {
                imm21 | (-1i32 << 21)
            } else {
                imm21
            };
            let pc_page = addr & !0xfff;
            pc_page.wrapping_add((signed_offset as i64 as u64) << 12)
        } else {
            return None;
        };

    // Check for ldr x16, [x16, #offset]
    let got_addr = if let decoder::Operation::LDST_POS(decoder::LDST_POS::LDR_Rt_ADDR_UIMM12(ldr)) =
        decoded2.operation
    {
        if ldr.rt() != 16 || ldr.rn() != 16 {
            return None;
        }
        let offset = (ldr.imm12() as u64).checked_shl(3)?;
        page_addr.checked_add(offset)?
    } else {
        return None;
    };

    // Check for br x16
    if let decoder::Operation::BRANCH_REG(decoder::BRANCH_REG::BR_Rn(br)) = decoded3.operation {
        if br.rn() != 16 {
            return None;
        }
    } else {
        return None;
    }

    // Validate GOT address is in reasonable range before dereferencing
    if got_addr < 0x1000 || got_addr > 0x7fffffffffff {
        return None;
    }

    // Read the supervisor function address from GOT
    let supervisor_addr = unsafe { *(got_addr as *const u64) };

    // Verify it's a supervisor address (outside guest text)
    if supervisor_addr >= ctx.text_start && supervisor_addr < ctx.text_end {
        return None;
    }

    Some(supervisor_addr)
}

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

    // Check if this is a GOT stub (adrp/ldr/br pattern)
    if let Some(supervisor_addr) = check_got_stub_at(ctx, start_addr) {
        trace!(
            "Translating GOT stub at 0x{:016x} -> supervisor 0x{:016x}",
            start_addr, supervisor_addr
        );
        let cache_addr: *mut u8 = ctx.text_allocator.start();
        let mut block = unsafe { TranslatedBlockBuilder::new(cache_addr) };

        // Save guest return address from x30 to x19 BEFORE calling supervisor
        // (blr will overwrite x30 with the return address in our translated code)
        // We use x19 because it's callee-saved - supervisor won't clobber it
        // stp x19, x20, [sp, #-16]!  - save x19/x20 to stack
        block.asm.emit(0xa9bf53f3);
        // mov x19, x30
        block.asm.emit(0xaa1e03f3);

        // Call the supervisor function
        block.asm.emit_ld_imm(16, supervisor_addr);
        block.asm.emit_blr(16);

        // After supervisor returns, dispatch to guest return address in x19
        // mov x16, x19
        block.asm.emit(0xaa1303f0);
        // ldp x19, x20, [sp], #16  - restore x19/x20 from stack
        block.asm.emit(0xa8c153f3);

        // Branch to dispatcher trampoline
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        block.asm.emit_b_imm(dispatcher_addr);

        let block = block.finish();
        ctx.text_allocator.reserve(block.size());
        super::flush_icache_range(cache_addr, block.size());
        ctx.code_cache.insert(start_addr, block.clone());
        trace!("GOT stub block cached at {:p}", cache_addr);
        return Ok(block);
    }

    let cache_addr: *mut u8 = ctx.text_allocator.start();
    let mut block = unsafe { TranslatedBlockBuilder::new(cache_addr) };
    let mut addr = start_addr;
    loop {
        if addr >= end_addr || !translate_insn(ctx, &mut block, addr, returnable)? {
            break;
        }
        addr += ARM64_INSN_SIZE as u64;
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
    returnable: bool,
) -> Result<bool> {
    if let Some(insn) = fetch_insn(ctx, addr) {
        if let Some(decoded) = decoder::decode(insn) {
            trace!(
                "Translating instruction at guest 0x{:016x} -> host 0x{:016x}: {}",
                addr,
                block.asm.addr(),
                decoded
            );
            match decoded.operation {
                decoder::Operation::EXCEPTION(excep) => match excep {
                    decoder::EXCEPTION::SVC_EXCEPTION(svc) => {
                        let svc_imm = svc.imm16_5();
                        block.emit_syscall_wrapper(svc_imm);
                        Ok(true)
                    }
                    _ => Err(Error::InstructionDecodeError(format!(
                        "Unhandled EXCEPTION at 0x{:016x}: {:?}",
                        addr, excep
                    ))),
                },
                decoder::Operation::BRANCH_IMM(branch) => match branch {
                    decoder::BRANCH_IMM::B_ADDR_PCREL26(b) => {
                        let imm26 = b.imm26();
                        let signed_offset = if imm26 & 0x2000000 != 0 {
                            (imm26 as i64) | (-1i64 << 26)
                        } else {
                            imm26 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        block.emit_exit_stub_branch(target_addr);
                        Ok(false)
                    }
                    decoder::BRANCH_IMM::BL_ADDR_PCREL26(b) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);

                        let imm26 = b.imm26();
                        let signed_offset = if imm26 & 0x2000000 != 0 {
                            (imm26 as i64) | (-1i64 << 26)
                        } else {
                            imm26 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        block.emit_exit_stub_branch(target_addr);
                        Ok(false)
                    }
                },
                decoder::Operation::CONDBRANCH(cond_branch) => match cond_branch {
                    decoder::CONDBRANCH::B__ADDR_PCREL19(b) => {
                        let imm19 = b.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        let cond = b.cond();
                        block.emit_exit_stub_cond_branch(cond, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                    decoder::CONDBRANCH::BC__ADDR_PCREL19(bc) => {
                        let imm19 = bc.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        let cond = bc.cond();
                        block.emit_exit_stub_cond_branch(cond, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                },
                decoder::Operation::BRANCH_REG(branch_reg) => match branch_reg {
                    decoder::BRANCH_REG::BR_Rn(br) => {
                        let reg = br.rn();
                        block.emit_exit_stub_indirect_branch(reg as u32);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BLR_Rn(blr) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blr.rn();
                        block.emit_exit_stub_indirect_branch(reg as u32);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::RET_Rn(ret) => {
                        if returnable {
                            block.emit(insn);
                        } else {
                            let reg = ret.rn();
                            block.emit_exit_stub_indirect_branch(reg as u32);
                        }
                        Ok(false)
                    }
                    _ => Err(Error::InstructionDecodeError(format!(
                        "Unhandled BRANCH_REG instruction at 0x{:016x}",
                        addr
                    ))),
                },
                decoder::Operation::PCRELADDR(pc_rel) => match pc_rel {
                    decoder::PCRELADDR::ADR_Rd_ADDR_PCREL21(adr) => {
                        let rd = adr.rd();
                        let imm21 = adr.immlo() as i32 | ((adr.immhi() as i32) << 2);
                        let signed_offset = if imm21 & 0x100000 != 0 {
                            imm21 | (-1i32 << 21)
                        } else {
                            imm21
                        };
                        let target_addr = addr.wrapping_add(signed_offset as u64);
                        block.asm.emit_ld_imm(rd, target_addr);
                        Ok(true)
                    }
                    decoder::PCRELADDR::ADRP_Rd_ADDR_ADRP(adrp) => {
                        let rd = adrp.rd();
                        let imm21 = adrp.immlo() as i32 | ((adrp.immhi() as i32) << 2);

                        let signed_offset = if imm21 & 0x100000 != 0 {
                            imm21 | (-1i32 << 21)
                        } else {
                            imm21
                        };
                        let pc_page = addr & !0xfff;
                        let page_addr = pc_page.wrapping_add((signed_offset as i64 as u64) << 12);
                        block.asm.emit_ld_imm(rd, page_addr);
                        Ok(true)
                    }
                },
                _ => {
                    block.emit(insn);
                    Ok(true)
                }
            }
        } else {
            Err(Error::InstructionDecodeError(format!(
                "Failed to decode instruction 0x{:08x} at 0x{:016x}",
                insn, addr
            )))
        }
    } else {
        trace!("End of translatable region at 0x{:016x}", addr);
        Ok(false)
    }
}

fn fetch_insn(ctx: &crate::runtime::ExecutionContext, addr: u64) -> Option<u32> {
    if addr >= ctx.text_start && addr + 4 <= ctx.text_end {
        Some(unsafe { std::ptr::read(addr as *const u32) })
    } else {
        trace!(
            "Attempted to fetch instruction at 0x{:016x}, outside text bounds 0x{:016x}-0x{:016x}",
            addr, ctx.text_start, ctx.text_end
        );
        None
    }
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
    /// `text_start` must be a valid pointer to a writable memory region of at least 8 bytes
    pub unsafe fn new(text_start: *mut u8) -> Self {
        // Skip first 8 bytes for supervisor state storage
        let asm = unsafe { Assembler::new(text_start.add(8)) };
        Self { text_start, asm }
    }

    pub fn emit(&mut self, insn: u32) {
        self.asm.emit(insn);
    }

    /// Generate optimized syscall handling using syscall wrapper
    pub fn emit_syscall_wrapper(&mut self, svc_imm: u32) {
        // DON'T overwrite X0! The guest has set up syscall arguments in registers.
        // Pass svc_imm in a different register that the wrapper can use.
        // Use X9 as a scratch register to pass svc_imm to the wrapper
        self.asm.emit_ld_imm(9, svc_imm as u64); // mov x9, #svc_imm

        // Call the assembly syscall wrapper that handles all register save/restore
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_ld_imm(30, wrapper_addr);
        self.asm.emit_blr(30); // call syscall_wrapper() - gets svc_imm from x9
    }

    pub fn emit_exit_stub_branch(&mut self, target_address: u64) {
        // Store target in x16 and branch to unified trampoline
        self.asm.emit_ld_imm(16, target_address); // x16 = target_address

        // Direct branch to unified dispatcher trampoline
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_b_imm(dispatcher_addr); // b dispatcher_trampoline
    }

    pub fn emit_exit_stub_cond_branch(
        &mut self,
        cond: u32,
        target_address: u64,
        fallthrough_address: u64,
    ) {
        // For conditional branches, we need to:
        // 1. Emit the conditional branch that checks the condition
        // 2. If condition is true: load target_address and jump to dispatcher
        // 3. If condition is false: load fallthrough_address and jump to dispatcher

        // The emit_ld_imm generates 4 instructions (movz + 3 movk)
        // The emit_b_imm generates 1 instruction
        // So the taken path is 5 instructions total

        // Emit conditional branch that jumps to taken path if condition is true
        // We need to skip 5 instructions for the fallthrough path
        self.asm.emit_b_cond(cond, 5 * 4); // Jump over fallthrough path if condition is true

        // Not taken (fallthrough) path: load fallthrough address and jump to dispatcher
        self.asm.emit_ld_imm(16, fallthrough_address); // x16 = fallthrough_address
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_b_imm(dispatcher_addr); // b dispatcher_trampoline

        // Taken path: load target address and jump to dispatcher
        self.asm.emit_ld_imm(16, target_address); // x16 = target_address
        self.asm.emit_b_imm(dispatcher_addr); // b dispatcher_trampoline
    }

    pub fn emit_exit_stub_indirect_branch(&mut self, src_reg: u32) {
        // Move target from source register to x16
        if src_reg != 16 {
            self.asm.emit_mov(16, src_reg); // mov x16, x<src_reg>
        }
        // If src_reg == 16, target is already in x16

        // Direct branch to unified dispatcher trampoline
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_b_imm(dispatcher_addr); // b dispatcher_trampoline
    }

    pub fn finish(self) -> TranslatedBlock {
        TranslatedBlock {
            text_start: self.text_start,
            text_size: self.asm.size() + 8, // Include the 8 bytes for supervisor state
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
    pub fn new(text_start: *mut u8, text_size: usize) -> Self {
        Self {
            text_start,
            text_size,
        }
    }

    pub fn text_start(&self) -> *mut u8 {
        self.text_start
    }

    pub fn print_code(&self) {
        // Skip first 8 bytes (supervisor state) and only print actual instructions
        for i in (8..self.text_size).step_by(std::mem::size_of::<u32>()) {
            let insn = unsafe { std::ptr::read(self.text_start.add(i) as *const u32) };
            if let Some(decoded) = decoder::decode(insn) {
                println!("{:08x}: {}", self.text_start as usize + i, decoded);
            } else {
                println!(
                    "{:08x}: <invalid instruction: 0x{:08x}>",
                    self.text_start as usize + i,
                    insn
                );
            }
        }
    }

    pub fn size(&self) -> usize {
        self.text_size
    }

    pub fn execute_returnable(&self, state: &mut CpuState) -> i32 {
        // For returnable execution, we still need to use execute_direct but catch the return
        // The difference is that the translated code will have direct ret instructions
        // that will return to us instead of going through the dispatcher
        unsafe {
            super::pthread_jit_write_protect_np(0);

            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            super::pthread_jit_write_protect_np(1);

            // Call translated code (starts 8 bytes after block start) and get return value
            let guest_code_start = self.text_start.add(8);

            let exit_code: u64;
            std::arch::asm!(
                "blr {code}",
                code = in(reg) guest_code_start,
                out("x0") exit_code,
            );
            exit_code as i32
        }
    }

    pub fn execute_direct(&self, state: &mut CpuState) -> ! {
        // Store cpu_state pointer at the reserved location (first 8 bytes of block)
        // Then jump to the actual guest code (starting at offset +8)
        unsafe {
            super::pthread_jit_write_protect_np(0);

            // Store cpu_state pointer at the beginning of the block
            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            super::pthread_jit_write_protect_np(1);

            // Jump to guest code (starts 8 bytes after block start)
            let guest_code_start = self.text_start.add(8);

            std::arch::asm!(
                "br {code}",
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }
}
