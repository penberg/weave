/// x86-64 assembler for runtime code generation
pub struct Assembler {
    /// Current position for emitting code
    text_ptr: *mut u8,
    /// Number of bytes emitted so far
    text_len: usize,
}

impl Assembler {
    /// Creates a new assembler that writes to the given memory location
    ///
    /// # Safety
    ///
    /// The caller must ensure that `text_ptr` points to valid writable memory
    pub unsafe fn new(text_ptr: *mut u8) -> Self {
        Self {
            text_ptr,
            text_len: 0,
        }
    }

    /// Returns the current address of the text pointer
    pub fn addr(&self) -> u64 {
        self.text_ptr as u64
    }

    /// Returns the number of bytes emitted so far
    pub fn size(&self) -> usize {
        self.text_len
    }

    /// Loads a 64-bit immediate value into a register
    /// MOV reg, imm64
    pub fn emit_mov_imm64(&mut self, reg: u8, value: u64) {
        // REX.W + B8+rd imm64
        let rex = 0x48 | if reg >= 8 { 1 } else { 0 };
        self.emit_u8(rex);
        self.emit_u8(0xb8 + (reg & 7));
        self.emit_u64(value);
    }

    /// Emits a direct jump (JMP rel32)
    pub fn emit_jmp_rel32(&mut self, target_addr: u64) {
        let pc = self.addr() + 5; // JMP rel32 is 5 bytes
        let offset = (target_addr as i64) - (pc as i64);

        if offset >= i32::MIN as i64 && offset <= i32::MAX as i64 {
            self.emit_u8(0xe9); // JMP rel32
            self.emit_u32(offset as i32 as u32);
        } else {
            // Target is out of range, use indirect jump via R11 (caller-saved, safe to clobber)
            // MOV R11, imm64 + JMP R11
            self.emit_mov_imm64(11, target_addr); // R11 = register 11
            self.emit_jmp_reg(11);
        }
    }

    /// Emits a conditional jump (Jcc rel32)
    pub fn emit_jcc_rel32(&mut self, condition: u8, target_addr: u64) {
        let pc = self.addr() + 6; // Jcc rel32 is 6 bytes (0x0f 0x8x + rel32)
        let offset = (target_addr as i64) - (pc as i64);
        assert!(
            offset >= i32::MIN as i64 && offset <= i32::MAX as i64,
            "Jump target out of range"
        );

        self.emit_u8(0x0f);
        self.emit_u8(0x80 + (condition & 0xf));
        self.emit_u32(offset as i32 as u32);
    }

    /// Emits a call instruction (CALL rel32)
    pub fn emit_call_rel32(&mut self, target_addr: u64) {
        let pc = self.addr() + 5;
        let offset = (target_addr as i64) - (pc as i64);

        if offset >= i32::MIN as i64 && offset <= i32::MAX as i64 {
            self.emit_u8(0xe8);
            self.emit_u32(offset as i32 as u32);
        } else {
            // Target is out of range, use indirect call via R11 (caller-saved, safe to clobber)
            // MOV R11, imm64 + CALL R11
            self.emit_mov_imm64(11, target_addr); // R11 = register 11
            self.emit_call_reg(11);
        }
    }

    /// Emits a CALL instruction to a register (CALL reg)
    pub fn emit_call_reg(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41); // REX.B prefix for R8-R15
        }
        self.emit_u8(0xff); // CALL r/m64
        self.emit_u8(0xd0 | (reg & 0x7)); // ModRM: 11 010 reg
    }

    /// Emits a JMP instruction to a register (JMP reg)
    pub fn emit_jmp_reg(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41); // REX.B prefix for R8-R15
        }
        self.emit_u8(0xff); // JMP r/m64
        self.emit_u8(0xe0 | (reg & 0x7)); // ModRM: 11 100 reg
    }

    /// Emits a PUSH instruction for 64-bit register
    /// PUSH r64
    pub fn emit_push_reg64(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41); // REX.B prefix for R8-R15
        }
        self.emit_u8(0x50 + (reg & 7)); // PUSH r64
    }

    /// Emits a POP instruction for 64-bit register
    /// POP r64
    pub fn emit_pop_reg64(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41); // REX.B prefix for R8-R15
        }
        self.emit_u8(0x58 + (reg & 7)); // POP r64
    }

    /// Emits a MOV instruction to copy one register to another
    /// MOV dst, src
    pub fn emit_mov_reg_to_reg(&mut self, dst: u8, src: u8) {
        // REX.W prefix (0x48) + optional REX.R and REX.B
        // For opcode 0x89 (MOV r/m, r):
        // - src goes in REG field (needs REX.R if src >= 8)
        // - dst goes in R/M field (needs REX.B if dst >= 8)
        let mut rex = 0x48;
        if src >= 8 {
            rex |= 0x04; // REX.R (source in REG field)
        }
        if dst >= 8 {
            rex |= 0x01; // REX.B (destination in R/M field)
        }
        self.emit_u8(rex);

        // MOV opcode
        self.emit_u8(0x89); // MOV r/m64, r64

        // ModRM byte: 11 (register mode) + src (reg field) + dst (r/m field)
        let modrm = 0xc0 | ((src & 7) << 3) | (dst & 7);
        self.emit_u8(modrm);
    }

    /// Emits code to move an indirect memory operand into a 64-bit register
    ///
    /// Converts a JMP/CALL [mem] instruction into MOV reg64, [mem]
    ///
    /// # Arguments
    /// * `dst_reg` - Destination register number (0-15)
    /// * `insn` - The instruction containing the memory operand
    pub fn emit_mov_indirect_to_reg64(&mut self, dst_reg: u8, insn: &iced_x86::Instruction) {
        // Check if it's RIP-relative addressing
        if insn.memory_base() == iced_x86::Register::RIP {
            // For RIP-relative addressing, we need to compute the absolute target address
            // since we're translating to a different location in memory
            //
            // Original guest instruction: JMP [rip+disp]
            // Guest RIP after instruction: insn.next_ip()
            // Absolute target: insn.next_ip() + insn.memory_displacement64()
            //
            // We'll load from this absolute address using a different approach:
            // Use R11 as a scratch register (caller-saved, safe to clobber)

            // For RIP-relative addressing, use ip_rel_memory_address() to get the
            // absolute runtime address. Since we create the decoder with the runtime
            // address (including ELF_BASE_ADDRESS), iced-x86 already calculates the
            // absolute address for us - no need to add ELF_BASE_ADDRESS again!
            let absolute_target = insn.ip_rel_memory_address();

            tracing::trace!(
                "RIP-relative indirect: Loading target from GOT address 0x{:x}",
                absolute_target
            );

            // MOV dst_reg, absolute_target
            self.emit_mov_imm64(dst_reg, absolute_target);

            // MOV dst_reg, [dst_reg]  - load the target address from GOT
            let mut rex = 0x48; // REX.W
            if dst_reg >= 8 {
                rex |= 0x05; // REX.R and REX.B (both source and dest are the same high register)
            }
            self.emit_u8(rex);
            self.emit_u8(0x8b); // MOV r64, r/m64
            self.emit_u8(0x00 | ((dst_reg & 7) << 3) | (dst_reg & 7)); // ModRM: 00 dst dst
        } else if insn.memory_base() != iced_x86::Register::None
            && insn.memory_index() == iced_x86::Register::None
        {
            // Simple base register addressing: MOV dst_reg, [base_reg]
            let base_reg = insn.memory_base().number() as u8;

            // REX prefix if needed
            let mut rex = 0x48; // REX.W
            if dst_reg >= 8 {
                rex |= 0x04; // REX.R (destination register)
            }
            if base_reg >= 8 {
                rex |= 0x01; // REX.B (base register)
            }
            self.emit_u8(rex);

            // MOV opcode
            self.emit_u8(0x8b); // MOV r64, r/m64

            // ModRM byte for [base_reg] with possible displacement
            let disp = insn.memory_displacement64() as i64;
            if disp == 0 && (base_reg & 7) != 5 {
                // Special case: RBP/R13 require displacement
                // [base_reg] with no displacement
                let modrm = 0x00 | ((dst_reg & 7) << 3) | (base_reg & 7); // Mod=00, Reg=dst_reg, R/M=base
                self.emit_u8(modrm);
                if (base_reg & 7) == 4 {
                    // RSP/R12 require SIB byte
                    self.emit_u8(0x24); // SIB: scale=0, index=none, base=RSP
                }
            } else if disp >= -128 && disp <= 127 {
                // [base_reg + disp8]
                let modrm = 0x40 | ((dst_reg & 7) << 3) | (base_reg & 7); // Mod=01, Reg=dst_reg, R/M=base
                self.emit_u8(modrm);
                if (base_reg & 7) == 4 {
                    // RSP/R12 require SIB byte
                    self.emit_u8(0x24); // SIB: scale=0, index=none, base=RSP
                }
                self.emit_u8(disp as i8 as u8);
            } else {
                // [base_reg + disp32]
                let modrm = 0x80 | ((dst_reg & 7) << 3) | (base_reg & 7); // Mod=10, Reg=dst_reg, R/M=base
                self.emit_u8(modrm);
                if (base_reg & 7) == 4 {
                    // RSP/R12 require SIB byte
                    self.emit_u8(0x24); // SIB: scale=0, index=none, base=RSP
                }
                self.emit_u32(disp as i32 as u32);
            }
        } else {
            // For other addressing modes (base+index*scale, etc.), we need more work
            panic!(
                "Unsupported memory addressing mode for indirect jump/call: base={:?}, index={:?}, scale={}",
                insn.memory_base(),
                insn.memory_index(),
                insn.memory_index_scale()
            );
        }
    }

    /// Emits MOVSD instruction to load from memory into XMM register
    /// MOVSD xmm, [reg]
    ///
    /// # Arguments
    /// * `xmm_reg` - XMM register number (0-15)
    /// * `base_reg` - Base register number (0-15)
    pub fn emit_movsd_xmm_from_reg(&mut self, xmm_reg: u8, base_reg: u8) {
        assert!(xmm_reg < 16, "Invalid XMM register number: {}", xmm_reg);
        assert!(base_reg < 16, "Invalid base register number: {}", base_reg);

        // MOVSD xmm, [reg]
        // Encoding: F2 [REX] 0F 10 /r
        //   F2       = REP prefix (for SSE2 scalar double)
        //   REX      = REX.B if base_reg >= 8
        //   0F 10    = MOVSD opcode
        //   ModRM    = mod=00 (indirect), reg=xmm_reg, r/m=base_reg

        const PREFIX_REP: u8 = 0xF2;
        const MOVSD_OPCODE_1: u8 = 0x0F;
        const MOVSD_OPCODE_2: u8 = 0x10;

        // Emit REP prefix
        self.emit_u8(PREFIX_REP);

        // Emit REX prefix if base register is R8-R15
        if base_reg >= 8 {
            self.emit_u8(0x41); // REX.B
        }

        // Emit opcode
        self.emit_u8(MOVSD_OPCODE_1);
        self.emit_u8(MOVSD_OPCODE_2);

        // Emit ModRM byte: mod=00 (indirect), reg=xmm, r/m=base
        let modrm = 0x00 | ((xmm_reg & 7) << 3) | (base_reg & 7);
        self.emit_u8(modrm);
    }

    /// Emit raw bytes
    pub fn emit_bytes(&mut self, bytes: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.text_ptr, bytes.len());
            self.text_ptr = self.text_ptr.add(bytes.len());
            self.text_len += bytes.len();
        }
    }

    fn emit_u8(&mut self, byte: u8) {
        unsafe {
            std::ptr::write(self.text_ptr, byte);
            self.text_ptr = self.text_ptr.add(1);
            self.text_len += 1;
        }
    }

    fn emit_u32(&mut self, value: u32) {
        unsafe {
            std::ptr::write(self.text_ptr as *mut u32, value);
            self.text_ptr = self.text_ptr.add(4);
            self.text_len += 4;
        }
    }

    fn emit_u64(&mut self, value: u64) {
        unsafe {
            std::ptr::write(self.text_ptr as *mut u64, value);
            self.text_ptr = self.text_ptr.add(8);
            self.text_len += 8;
        }
    }
}
