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
        return Err(Error::InstructionDecodeError(format!(
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
            return Ok(true);
        }
        iced_x86::Code::Jmp_rel32_64 | iced_x86::Code::Jmp_rel8_64 => {
            let target = insn.near_branch64();
            block.emit_exit_stub_branch(target);
            return Ok(false);
        }
        iced_x86::Code::Call_rel32_64 => {
            let target = insn.near_branch64();
            let return_addr = addr + insn.len() as u64;
            block.emit_call_exit_stub(target, return_addr);
            return Ok(false);
        }
        iced_x86::Code::Retnq => {
            if returnable {
                block.emit_bytes(&bytes[0..insn.len()]);
            } else {
                block.emit_ret_exit_stub();
            }
            return Ok(false);
        }
        // Conditional jumps
        code if is_conditional_jump(code) => {
            let target = insn.near_branch64();
            let fallthrough = addr + insn.len() as u64;
            let condition = get_condition_code(code);
            block.emit_exit_stub_cond_branch(condition, target, fallthrough);
            return Ok(false);
        }
        _ => {
            // Copy instruction as-is for identity translation
            block.emit_bytes(&bytes[0..insn.len()]);
            return Ok(true);
        }
    }
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

    /// Generate syscall handling wrapper
    pub fn emit_syscall_wrapper(&mut self) {
        let wrapper_addr = dispatcher::syscall_wrapper as *const () as u64;
        self.asm.emit_call_rel32(wrapper_addr);
    }

    pub fn emit_exit_stub_branch(&mut self, target_address: u64) {
        // Load target address into a register and call dispatcher
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;

        // MOV RDI, target_address (first argument to dispatcher)
        self.asm.emit_mov_imm64(7, target_address); // RDI = register 7
        // JMP to dispatcher
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_call_exit_stub(&mut self, target_address: u64, _return_address: u64) {
        // For calls, we need to handle the return address
        // Load target and jump to dispatcher
        self.asm.emit_mov_imm64(7, target_address);
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);
    }

    pub fn emit_ret_exit_stub(&mut self) {
        // For indirect jumps/returns, we need to get the target from the stack
        // This is simplified - we'll pop the return address and jump to dispatcher
        // TODO: implement properly
        self.asm.emit_ret();
    }

    pub fn emit_exit_stub_cond_branch(
        &mut self,
        condition: u8,
        target_address: u64,
        fallthrough_address: u64,
    ) {
        // Calculate size of fallthrough path
        // MOV RDI, imm64 (10 bytes) + JMP rel32 (5 bytes) = 15 bytes
        let fallthrough_size = 15;

        // Emit conditional jump to target path (inverted condition)
        let taken_addr = self.asm.addr() + 6 + fallthrough_size as u64;
        self.asm.emit_jcc_rel32(condition, taken_addr);

        // Fallthrough path
        self.asm.emit_mov_imm64(7, fallthrough_address);
        let dispatcher_addr = dispatcher::dispatcher_trampoline as *const () as u64;
        self.asm.emit_jmp_rel32(dispatcher_addr);

        // Taken path
        self.asm.emit_mov_imm64(7, target_address);
        self.asm.emit_jmp_rel32(dispatcher_addr);
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

            // Jump to guest code
            let guest_code_start = self.text_start.add(8);
            std::arch::asm!(
                "jmp {code}",
                code = in(reg) guest_code_start,
                options(noreturn)
            );
        }
    }
}
