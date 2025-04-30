use super::{CpuState, X86_MAX_INSN_SIZE, assembler::Assembler, dispatcher};
use crate::{Error, Result};
use iced_x86::{Decoder, DecoderOptions};
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
    returnable: bool,
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
            if returnable {
                block.emit_bytes(&bytes[0..insn.len()]);
            } else {
                block.emit_ret_exit_stub();
            }
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

                    block.emit_mov_reg64_imm64(iced_x86::Register::R11, target_addr);
                    block.emit_movsd_xmm_from_reg(xmm_reg, iced_x86::Register::R11);
                } else {
                    // Unhandled RIP-relative instruction - ERROR!
                    return Err(Error::InstructionDecode(format!(
                        "Unhandled RIP-relative instruction at 0x{:x}: {:?}",
                        addr, insn
                    )));
                }
            } else {
                // Copy instruction as-is for identity translation
                block.emit_bytes(&bytes[0..insn.len()]);
            }
            Ok(true)
        }
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

    /// Generate syscall handling wrapper
    pub fn emit_syscall_wrapper(&mut self) {
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_call_rel32(wrapper_addr);
    }

    pub fn emit_exit_stub_branch(&mut self, target_address: u64) {
        // Load target address into RCX (DynamoRIO approach - doesn't conflict with args!)
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;

        // MOV RCX, target_address (dispatch register)
        self.asm.emit_mov_imm64(1, target_address); // RCX = register 1
        // JMP to dispatcher
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_call_exit_stub(&mut self, target_address: u64, return_address: u64) {
        // For calls, we need to:
        // 1. Push return address onto guest stack (RSP currently points to guest stack)
        // 2. Load target address into RCX for dispatcher
        // 3. Jump to dispatcher (which will switch to host stack)

        // MOV R11, return_address
        self.asm.emit_mov_imm64(11, return_address);
        // PUSH R11 (this pushes onto GUEST stack, which is what we want)
        self.asm.emit_push_reg64(11);

        // MOV RCX, target_address (dispatch register)
        self.asm.emit_mov_imm64(1, target_address);

        // JMP to dispatcher
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_ret_exit_stub(&mut self) {
        // For returns, we need to:
        // 1. Pop return address from guest stack (RSP currently points to guest stack)
        // 2. Load it into RCX for dispatcher
        // 3. Jump to dispatcher

        // POP RCX (pops from GUEST stack, loads return address into RCX)
        self.asm.emit_pop_reg64(1); // RCX = register 1

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
        self.asm.emit_mov_imm64(1, fallthrough_address); // RCX = register 1
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
        self.asm.emit_mov_imm64(1, target_address); // RCX = register 1
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_exit_stub_indirect_jump(&mut self, insn: &iced_x86::Instruction) {
        // For indirect jumps, we need to:
        // 1. Load the target address into RDI
        // 2. Jump to dispatcher

        use iced_x86::OpKind;

        match insn.op0_kind() {
            OpKind::Register => {
                // JMP reg (e.g., jmp rax)
                let reg = insn.op0_register();
                let reg_num = register_to_number(reg);

                // Move target to RCX (dispatch register - doesn't conflict with args!)
                if reg_num != 1 {
                    self.asm.emit_mov_reg_to_reg(1, reg_num); // MOV RCX, reg
                }

                // Jump to dispatcher
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            OpKind::Memory => {
                // JMP [mem] (e.g., jmp qword ptr [rax], jmp qword ptr [rip+offset])
                // Load the target address from memory into R11
                self.asm.emit_mov_indirect_to_reg64(11, insn); // R11 = register 11

                // Move R11 to RCX (dispatch register)
                self.asm.emit_mov_reg_to_reg(1, 11); // MOV RCX, R11

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
        // 2. Load the target address into RCX (dispatch register)
        // 3. Jump to dispatcher

        use iced_x86::OpKind;

        // Push return address onto guest stack
        self.asm.emit_mov_imm64(11, return_address); // MOV R11, return_address
        self.asm.emit_push_reg64(11); // PUSH R11

        match insn.op0_kind() {
            OpKind::Register => {
                // CALL reg (e.g., call rax)
                let reg = insn.op0_register();
                let reg_num = register_to_number(reg);

                // Move target to RCX (dispatch register)
                if reg_num != 1 {
                    self.asm.emit_mov_reg_to_reg(1, reg_num); // MOV RCX, reg
                }

                // Jump to dispatcher
                let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
                self.asm.emit_jmp_rel32(dispatcher_addr);
            }
            OpKind::Memory => {
                // CALL [mem] (e.g., call qword ptr [rax], call qword ptr [rip+offset])
                // Load into R11, then move to RCX

                self.asm.emit_mov_indirect_to_reg64(11, insn); // R11 = register 11

                // Move R11 to RCX (dispatch register)
                self.asm.emit_mov_reg_to_reg(1, 11); // MOV RCX, R11

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

    pub fn execute_returnable(&self, state: &mut CpuState) -> i32 {
        unsafe {
            // Store cpu_state pointer at the beginning
            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            // Call translated code
            let guest_code_start = self.text_start.add(8);
            let exit_code: u64;
            std::arch::asm!(
                "call {code}",
                code = in(reg) guest_code_start,
                out("rax") exit_code,
            );
            exit_code as i32
        }
    }

    pub fn execute_direct(&self, state: &mut CpuState) -> ! {
        unsafe {
            // Store cpu_state pointer
            std::ptr::write(self.text_start as *mut u64, state as *mut CpuState as u64);

            // Jump to translated guest code
            // We use the natural program stack (the one Rust is currently using)
            // instead of switching to a separate stack. This is more transparent
            // and matches how a real program would execute.
            let guest_code_start = self.text_start.add(8);
            std::arch::asm!(
                "jmp {code}",
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }
}
