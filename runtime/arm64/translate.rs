use super::{ARM64_INSN_SIZE, CpuState, assembler::Assembler, dispatcher};
use crate::{Error, Result};
use disarm64::decoder;
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
                    decoder::EXCEPTION::BRK_EXCEPTION(brk) => {
                        // BRK is used for breakpoints/traps. On Darwin, BRK #1 is __builtin_trap()
                        // Emit code to call our trap handler at runtime
                        let imm = brk.imm16_5();
                        block.emit_brk_trap(addr, imm);
                        Ok(false) // End block after trap
                    }
                    _ => Err(Error::InstructionDecode(format!(
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
                decoder::Operation::COMPBRANCH(comp_branch) => match comp_branch {
                    decoder::COMPBRANCH::CBZ_Rt_ADDR_PCREL19(cbz) => {
                        let rt = cbz.rt();
                        let imm19 = cbz.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // CBZ: branch if Rt == 0, which is condition EQ (0)
                        // First emit: cmp Rt, #0 to set flags
                        block.asm.emit_cmp_imm(rt, 0);
                        block.emit_exit_stub_cond_branch(0, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                    decoder::COMPBRANCH::CBNZ_Rt_ADDR_PCREL19(cbnz) => {
                        let rt = cbnz.rt();
                        let imm19 = cbnz.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // CBNZ: branch if Rt != 0, which is condition NE (1)
                        // First emit: cmp Rt, #0 to set flags
                        block.asm.emit_cmp_imm(rt, 0);
                        block.emit_exit_stub_cond_branch(1, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                },
                decoder::Operation::TESTBRANCH(test_branch) => match test_branch {
                    decoder::TESTBRANCH::TBZ_Rt_BIT_NUM_ADDR_PCREL14(tbz) => {
                        let rt = tbz.rt();
                        let imm14 = tbz.imm14();
                        let bit_num = (tbz.b5() << 5) | tbz.b40();
                        let signed_offset = if imm14 & 0x2000 != 0 {
                            (imm14 as i64) | (-1i64 << 14)
                        } else {
                            imm14 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // TBZ: branch if bit is zero
                        // Use tst (ands xzr, Rt, #(1 << bit_num)) to set Z flag
                        block.asm.emit_tst_imm(rt, bit_num);
                        // Branch if Z flag is set (condition EQ = 0)
                        block.emit_exit_stub_cond_branch(0, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                    decoder::TESTBRANCH::TBNZ_Rt_BIT_NUM_ADDR_PCREL14(tbnz) => {
                        let rt = tbnz.rt();
                        let imm14 = tbnz.imm14();
                        let bit_num = (tbnz.b5() << 5) | tbnz.b40();
                        let signed_offset = if imm14 & 0x2000 != 0 {
                            (imm14 as i64) | (-1i64 << 14)
                        } else {
                            imm14 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // TBNZ: branch if bit is not zero
                        // Use tst (ands xzr, Rt, #(1 << bit_num)) to set Z flag
                        block.asm.emit_tst_imm(rt, bit_num);
                        // Branch if Z flag is not set (condition NE = 1)
                        block.emit_exit_stub_cond_branch(1, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                },
                decoder::Operation::BRANCH_REG(branch_reg) => match branch_reg {
                    decoder::BRANCH_REG::BR_Rn(br) => {
                        let reg = br.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    // BRAA/BRAAZ/BRAB/BRABZ: Branch with pointer authentication
                    // We treat these as regular BR since we don't implement PAC
                    decoder::BRANCH_REG::BRAA_Rn_Rd_SP(braa) => {
                        let reg = braa.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BRAAZ_Rn(braaz) => {
                        let reg = braaz.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BRAB_Rn_Rd_SP(brab) => {
                        let reg = brab.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BRABZ_Rn(brabz) => {
                        let reg = brabz.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BLR_Rn(blr) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blr.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    // BLRAA/BLRAAZ/BLRAB/BLRABZ: Branch with link and pointer authentication
                    // We treat these as regular BLR since we don't implement PAC
                    decoder::BRANCH_REG::BLRAA_Rn_Rd_SP(blraa) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blraa.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BLRAAZ_Rn(blraaz) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blraaz.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BLRAB_Rn_Rd_SP(blrab) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blrab.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::BLRABZ_Rn(blrabz) => {
                        let return_addr = addr + 4;
                        block.asm.emit_ld_imm(30, return_addr);
                        let reg = blrabz.rn();
                        block.emit_exit_stub_indirect_branch(reg);
                        Ok(false)
                    }
                    decoder::BRANCH_REG::RET_Rn(ret) => {
                        if returnable {
                            block.emit(insn);
                        } else {
                            let reg = ret.rn();
                            block.emit_exit_stub_indirect_branch(reg);
                        }
                        Ok(false)
                    }
                    // RETAA/RETAB: Return with pointer authentication
                    // We treat these as regular RET since we don't implement PAC
                    decoder::BRANCH_REG::RETAA(_) | decoder::BRANCH_REG::RETAB(_) => {
                        if returnable {
                            block.emit(insn);
                        } else {
                            // RETAA/RETAB always use x30 as the return register
                            block.emit_exit_stub_indirect_branch(30);
                        }
                        Ok(false)
                    }
                    _ => Err(Error::InstructionDecode(format!(
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
            Err(Error::InstructionDecode(format!(
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

    /// Handle BRK trap instructions
    pub fn emit_brk_trap(&mut self, addr: u64, imm: u32) {
        // Emit code to call brk_trap_handler(addr, imm) which aborts
        // Load arguments
        self.asm.emit_ld_imm(0, addr); // x0 = addr
        self.asm.emit_ld_imm(1, imm as u64); // x1 = imm

        // Call the trap handler
        let handler_addr = dispatcher::brk_trap_handler as *const () as u64;
        self.asm.emit_ld_imm(16, handler_addr);
        self.asm.emit_blr(16); // blr x16 - call handler (never returns)
    }

    /// Generate optimized syscall handling using syscall wrapper
    pub fn emit_syscall_wrapper(&mut self, svc_imm: u32) {
        // DON'T overwrite X0! The guest has set up syscall arguments in registers.
        // Pass svc_imm in a different register that the wrapper can use.
        // Use X9 as a scratch register to pass svc_imm to the wrapper
        self.asm.emit_ld_imm(9, svc_imm as u64); // mov x9, #svc_imm

        // Save x30 (link register) before clobbering it - the guest's return address
        // must be preserved across syscalls. Use x10 as a temporary.
        self.asm.emit_mov(10, 30); // mov x10, x30

        // Call the assembly syscall wrapper that handles all register save/restore
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_ld_imm(30, wrapper_addr);
        self.asm.emit_blr(30); // call syscall_wrapper() - gets svc_imm from x9

        // Restore x30 from x10 - this is critical! Without this, x30 would contain
        // the code cache return address, causing incorrect returns.
        self.asm.emit_mov(30, 10); // mov x30, x10
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

    pub fn execute_returnable(&self, state: &mut CpuState) -> ! {
        // For returnable execution, we set x30 to a sentinel value.
        // When main() returns, the ret instruction is translated as an indirect
        // branch that goes through the dispatcher. The dispatcher detects the
        // sentinel and calls std::process::exit with the exit code.
        unsafe {
            super::pthread_jit_write_protect_np(0);

            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            super::pthread_jit_write_protect_np(1);

            // Call translated code (starts 8 bytes after block start)
            let guest_code_start = self.text_start.add(8);

            // Set up initial guest registers
            // x0 = argc, x1 = argv, x29 = frame pointer/stack pointer
            let x0 = state.regs[0];
            let x1 = state.regs[1];
            let x29 = state.regs[29];
            let sentinel = dispatcher::MAIN_RETURN_SENTINEL;

            tracing::debug!(
                "execute_returnable: x0={}, x1=0x{:x}, x29=0x{:x}, code={:p}",
                x0,
                x1,
                x29,
                guest_code_start
            );

            // Set up guest registers and branch to translated code.
            // This never returns - the guest code will eventually call exit() or
            // main() will return (triggering the sentinel detection in the dispatcher).
            std::arch::asm!(
                // Switch to guest stack
                "mov sp, {initial_sp}",
                // Set up remaining guest registers
                "mov x29, {initial_sp}",
                "mov x30, {sentinel}",  // Return address = sentinel
                "mov x1, {argv}",
                "mov x0, {argc}",
                // Branch to translated code (don't use blr since we set x30 manually)
                "br {code}",
                initial_sp = in(reg) x29,
                sentinel = in(reg) sentinel,
                argv = in(reg) x1,
                argc = in(reg) x0,
                code = in(reg) guest_code_start,
                options(noreturn)
            );
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

            // Set up initial guest registers and branch to code
            // x0 = argc, x1 = argv, x29 = frame pointer (from state.regs)
            // SP is set from regs[29] (we use x29 as the initial SP since we can't
            // store SP in the regs array directly)
            let x0 = state.regs[0];
            let x1 = state.regs[1];
            let x29 = state.regs[29];

            tracing::debug!(
                "execute_direct: x0={}, x1=0x{:x}, x29=0x{:x}, code={:p}",
                x0,
                x1,
                x29,
                guest_code_start
            );

            // Use specific register constraints to avoid conflicts
            std::arch::asm!(
                "mov sp, {initial_sp}",   // Set stack pointer to guest stack FIRST
                "mov x29, {initial_sp}",  // Set frame pointer
                "mov x1, {argv}",         // Set argv
                "mov x0, {argc}",         // Set argc LAST to avoid clobbering
                "br {code}",
                initial_sp = in(reg) x29,
                argv = in(reg) x1,
                argc = in(reg) x0,
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }
}
