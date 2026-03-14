use super::{ARM64_INSN_SIZE, CpuState, assembler::Assembler, dispatcher};
use crate::{Error, Result};
use disarm64::decoder;
use tracing::trace;

/// Immediate value for conditional branches to skip the fallthrough dispatch path.
/// The fallthrough path is 5 instructions (4 from emit_ld_imm + 1 from emit_b_imm).
/// Since branch offsets are PC-relative from the branch instruction itself, the
/// immediate is 5 + 1 = 6 (target = PC + 6*4 = first instruction of the taken path).
const FALLTHROUGH_SKIP_IMM: u32 = 6;

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
                        let imm19 = cbz.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // Re-emit the original CBZ/CBNZ with patched offset to the
                        // taken exit stub. This preserves the sf bit (32-bit vs 64-bit
                        // register check) and does NOT modify NZCV flags.
                        block.emit_exit_stub_patched_branch(insn, 0x7ffff << 5, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                    decoder::COMPBRANCH::CBNZ_Rt_ADDR_PCREL19(cbnz) => {
                        let imm19 = cbnz.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        block.emit_exit_stub_patched_branch(insn, 0x7ffff << 5, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                },
                decoder::Operation::TESTBRANCH(test_branch) => match test_branch {
                    decoder::TESTBRANCH::TBZ_Rt_BIT_NUM_ADDR_PCREL14(tbz) => {
                        let imm14 = tbz.imm14();
                        let signed_offset = if imm14 & 0x2000 != 0 {
                            (imm14 as i64) | (-1i64 << 14)
                        } else {
                            imm14 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        // Re-emit the original TBZ/TBNZ with patched offset.
                        // Preserves bit-test semantics and does NOT modify NZCV.
                        block.emit_exit_stub_patched_branch(insn, 0x3fff << 5, target_addr, fallthrough_addr);
                        Ok(false)
                    }
                    decoder::TESTBRANCH::TBNZ_Rt_BIT_NUM_ADDR_PCREL14(tbnz) => {
                        let imm14 = tbnz.imm14();
                        let signed_offset = if imm14 & 0x2000 != 0 {
                            (imm14 as i64) | (-1i64 << 14)
                        } else {
                            imm14 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let fallthrough_addr = addr + 4;
                        block.emit_exit_stub_patched_branch(insn, 0x3fff << 5, target_addr, fallthrough_addr);
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
                decoder::Operation::LOADLIT(loadlit) => match loadlit {
                    decoder::LOADLIT::LDR_Rt_ADDR_PCREL19(ldr) => {
                        let rt = ldr.rt();
                        let imm19 = ldr.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let opc = (insn >> 30) & 0x3;
                        block.asm.emit_ld_imm(rt, target_addr);
                        if opc == 0 {
                            block.asm.emit_ldr_w(rt, rt);
                        } else {
                            block.asm.emit_ldr_x(rt, rt);
                        }
                        Ok(true)
                    }
                    decoder::LOADLIT::LDR_Ft_ADDR_PCREL19(ldr) => {
                        let rt = ldr.rt();
                        let imm19 = ldr.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        let opc = (insn >> 30) & 0x3;
                        // Use x17 as scratch (intra-procedure-call scratch register)
                        block.asm.emit_ld_imm(17, target_addr);
                        match opc {
                            0 => block.asm.emit_ldr_s(rt, 17),
                            1 => block.asm.emit_ldr_d(rt, 17),
                            _ => block.asm.emit_ldr_q(rt, 17),
                        }
                        Ok(true)
                    }
                    decoder::LOADLIT::LDRSW_Rt_ADDR_PCREL19(ldr) => {
                        let rt = ldr.rt();
                        let imm19 = ldr.imm19();
                        let signed_offset = if imm19 & 0x40000 != 0 {
                            (imm19 as i64) | (-1i64 << 19)
                        } else {
                            imm19 as i64
                        };
                        let target_addr = addr.wrapping_add((signed_offset << 2) as u64);
                        block.asm.emit_ld_imm(rt, target_addr);
                        block.asm.emit_ldrsw(rt, rt);
                        Ok(true)
                    }
                    decoder::LOADLIT::PRFM_PRFOP_ADDR_PCREL19(_) => {
                        // Prefetch is a performance hint, not required for correctness
                        Ok(true)
                    }
                },
                _ => {
                    block.emit(insn);
                    Ok(true)
                }
            }
        } else {
            // Hit non-instruction data (e.g. literal pool embedded in the text
            // section). End the block — the data lives in guest memory and is
            // accessed by translated LDR literal sequences, not executed.
            Ok(false)
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
        // Avoid clobbering guest GPRs before the wrapper saves state.
        // Pass svc_imm via x17 (IP1), and save/restore LR on the stack.
        self.asm.emit_ld_imm(17, svc_imm as u64); // x17 := svc_imm

        // Push guest LR (like MAMBO does) before BLR clobbers x30
        self.asm.emit_push_lr();

        // Call the assembly syscall wrapper that handles all register save/restore
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_ld_imm(30, wrapper_addr);
        self.asm.emit_blr(30); // wrapper reads svc_imm from saved x17

        // Restore guest LR
        self.asm.emit_pop_lr();
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
        // Emit conditional branch that jumps to taken path if condition is true.
        // Skip offset = FALLTHROUGH_SKIP_IMM instructions (4 from ld_imm + 1 from b_imm).
        self.asm
            .emit_b_cond(cond, FALLTHROUGH_SKIP_IMM as i32 * 4);
        self.emit_dispatch_pair(fallthrough_address, target_address);
    }

    /// Exit stub for CBZ/CBNZ and TBZ/TBNZ instructions.
    ///
    /// Re-emits the original instruction with a patched immediate offset that
    /// jumps to the taken exit path. This preserves:
    /// - The sf bit (32-bit Wn vs 64-bit Xn register check for CBZ/CBNZ)
    /// - Bit-test semantics (b5:b40 bit position for TBZ/TBNZ)
    /// - NZCV flags (these instructions do not modify condition flags)
    ///
    /// `imm_mask` selects which bits hold the PC-relative offset:
    /// - CBZ/CBNZ: `0x7ffff << 5` (imm19, bits [23:5])
    /// - TBZ/TBNZ: `0x3fff << 5`  (imm14, bits [18:5])
    pub fn emit_exit_stub_patched_branch(
        &mut self,
        insn: u32,
        imm_mask: u32,
        target_address: u64,
        fallthrough_address: u64,
    ) {
        let patched = (insn & !imm_mask) | ((FALLTHROUGH_SKIP_IMM as u32) << 5);
        self.asm.emit(patched);
        self.emit_dispatch_pair(fallthrough_address, target_address);
    }

    /// Emits the fallthrough + taken dispatch pair shared by all conditional
    /// exit stubs. The caller must have already emitted the conditional branch
    /// instruction whose taken path skips FALLTHROUGH_SKIP_IMM instructions.
    fn emit_dispatch_pair(&mut self, fallthrough_address: u64, target_address: u64) {
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        // Fallthrough path: load fallthrough address and jump to dispatcher
        self.asm.emit_ld_imm(16, fallthrough_address);
        self.asm.emit_b_imm(dispatcher_addr);
        // Taken path: load target address and jump to dispatcher
        self.asm.emit_ld_imm(16, target_address);
        self.asm.emit_b_imm(dispatcher_addr);
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
