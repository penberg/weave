//! ARM64 assembler for runtime code generation.
//!
//! This module provides a lightweight assembler for generating ARM64 machine code
//! at runtime. It supports common instructions needed for JIT compilation.

/// ARM64 assembler that emits machine code directly to memory.
pub struct Assembler {
    /// Current position for emitting code.
    text_ptr: *mut u8,
    /// Number of bytes emitted so far.
    text_len: usize,
}

impl Assembler {
    /// Creates a new assembler that writes to the given memory location.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `text_ptr` points to valid writable memory
    /// with sufficient space for the generated code.
    pub unsafe fn new(text_ptr: *mut u8) -> Self {
        Self {
            text_ptr,
            text_len: 0,
        }
    }

    /// Returns the current address of the text pointer.
    pub fn addr(&self) -> u64 {
        self.text_ptr as u64
    }

    /// Returns the number of bytes emitted so far.
    pub fn size(&self) -> usize {
        self.text_len
    }

    /// Loads a 64-bit immediate value into a register.
    ///
    /// Uses a MOVZ/MOVK sequence to load the value in 16-bit chunks.
    /// - MOVZ loads the lowest 16 bits and zeros the rest
    /// - MOVK loads subsequent 16-bit chunks without affecting other bits
    ///
    /// # Arguments
    ///
    /// * `reg` - Target register (0-31)
    /// * `value` - 64-bit immediate value to load
    pub fn emit_ld_imm(&mut self, reg: u32, value: u64) {
        // MOVZ: Load lowest 16 bits, zero others
        let insn = 0xd2800000 | (reg & 0x1f) | (((value & 0xFFFF) as u32) << 5);
        self.emit(insn);

        // MOVK: Load bits 16-31 if needed
        if value > 0xFFFF {
            let insn = 0xf2a00000 | (reg & 0x1f) | ((((value >> 16) & 0xFFFF) as u32) << 5);
            self.emit(insn);
        }

        // MOVK: Load bits 32-47 if needed
        if value > 0xFFFFFFFF {
            let insn = 0xf2c00000 | (reg & 0x1f) | ((((value >> 32) & 0xFFFF) as u32) << 5);
            self.emit(insn);
        }

        // MOVK: Load bits 48-63 if needed
        if value > 0xFFFFFFFFFFFF {
            let insn = 0xf2e00000 | (reg & 0x1f) | ((((value >> 48) & 0xFFFF) as u32) << 5);
            self.emit(insn);
        }
    }

    /// Emits a branch with link to register (BLR) instruction.
    ///
    /// Branches to the address in the specified register and stores the
    /// return address in the link register (x30).
    ///
    /// # Arguments
    ///
    /// * `reg` - Register containing target address (0-31)
    pub fn emit_blr(&mut self, reg: u32) {
        self.emit(0xd63f0000 | ((reg & 0x1f) << 5));
    }

    /// Emits a register-to-register move instruction.
    ///
    /// Implemented as `ORR xD, xzr, xN` which copies the value from
    /// source to destination register.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination register (0-31)
    /// * `src` - Source register (0-31)
    pub fn emit_mov(&mut self, dest: u32, src: u32) {
        self.emit(0xaa0003e0 | (dest & 0x1f) | ((src & 0x1f) << 16));
    }

    /// Emits a branch (B) instruction to an immediate address.
    ///
    /// Calculates the PC-relative offset and emits a direct branch.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - Absolute address to branch to
    ///
    /// # Panics
    ///
    /// Panics if the target is out of the 26-bit signed range.
    pub fn emit_b_imm(&mut self, target_addr: u64) {
        let pc = self.addr();
        let offset = (target_addr as i64) - (pc as i64);

        assert!(
            offset >= -134217728 && offset <= 134217724 && offset % 4 == 0,
            "Branch target out of range: offset={}, pc=0x{:x}, target=0x{:x}",
            offset,
            pc,
            target_addr
        );

        let imm26 = ((offset / 4) & 0x3ffffff) as u32;
        self.emit(0x14000000 | imm26);
    }

    /// Emits a conditional branch instruction (b.cond).
    ///
    /// # Arguments
    ///
    /// * `cond` - Condition code (0-15)
    /// * `offset` - Signed offset in bytes (must be 4-byte aligned and within 19-bit range)
    pub fn emit_b_cond(&mut self, cond: u32, offset: i32) {
        assert!(
            offset >= -1048576 && offset <= 1048572 && offset % 4 == 0,
            "Conditional branch offset out of range: offset={}",
            offset
        );
        assert!(cond <= 15, "Invalid condition code: {}", cond);

        let imm19 = ((offset / 4) & 0x7ffff) as u32;
        // B.cond encoding: 0101010_0_imm19_0_cond
        let insn = 0x54000000 | (imm19 << 5) | (cond & 0xf);
        self.emit(insn);
    }

    /// Emits a raw 32-bit instruction.
    pub fn emit(&mut self, insn: u32) {
        unsafe {
            std::ptr::write(self.text_ptr as *mut u32, insn);
            self.text_ptr = self.text_ptr.add(4);
            self.text_len += 4;
        }
    }
}
