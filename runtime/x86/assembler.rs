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
        assert!(
            offset >= i32::MIN as i64 && offset <= i32::MAX as i64,
            "Jump target out of range"
        );

        self.emit_u8(0xe9); // JMP rel32
        self.emit_u32(offset as i32 as u32);
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
            self.emit_call_r11();
        }
    }

    /// Emits a call to R11 (CALL R11)
    pub fn emit_call_r11(&mut self) {
        self.emit_u8(0x41); // REX.B prefix for R11
        self.emit_u8(0xff); // CALL r/m64
        self.emit_u8(0xd3); // ModRM: 11 010 011 (CALL r11)
    }

    /// Emits a return instruction (RET)
    pub fn emit_ret(&mut self) {
        self.emit_u8(0xc3);
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
