//! Weave - A dynamic binary translator and JIT runtime.
//!
//! Weave is a Just-In-Time (JIT) compilation system that translates guest binary code
//! to host-native code at runtime. It provides infrastructure for executing programs
//! compiled for one architecture on another, or for instrumenting and analyzing
//! program execution.
//!
//! # Modules
//!
//! - [`runtime`] - Core JIT execution engine and code translation
//! - [`mmap`] - Memory-mapped file handling
//! - [`sys`] - Platform-specific system interfaces (Linux, macOS)
//! - [`libc`] - Deterministic C library function implementations
//!
//! # Error Handling
//!
//! All operations use the consolidated [`Error`] type, which provides specific
//! error variants for different failure modes (instruction decode, I/O, linking, etc.).

pub mod libc;
pub mod symbols;
pub mod sys;

pub mod mmap;
pub mod runtime;

/// Consolidated error type for all Weave operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("instruction decode error: {0}")]
    InstructionDecode(String),

    #[error("object format error: {0}")]
    ObjectFormat(#[from] ObjectFormatError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("dynamic linker error: {0}")]
    DynamicLinker(String),

    #[error("memory mapping error: {0}")]
    MemoryMapping(String),
}

/// Error type for object file format parsing and loading
#[derive(Debug, thiserror::Error)]
pub enum ObjectFormatError {
    #[error("not a valid object file")]
    InvalidFormat,

    #[error("goblin parse error: {0}")]
    GoblinError(#[from] goblin::error::Error),

    #[cfg(target_os = "macos")]
    #[error("mach-o error: {0}")]
    MachError(#[from] sys::darwin::dyld::MachError),

    #[error("cannot run binary for {binary_arch} architecture on {host_arch} host")]
    UnsupportedArch { binary_arch: String, host_arch: String },

    #[error("text segment is missing")]
    MissingTextSegment,

    #[error(
        "executable is not PIE (Position Independent Executable) - only PIE executables are supported"
    )]
    NotPIE,
}

pub type Result<T> = core::result::Result<T, Error>;

pub use mmap::MappedFile;

pub use runtime::{CpuState, ExecutionContext};

/// Probe the host architecture
#[cfg(target_os = "macos")]
pub fn probe_host_arch() -> sys::darwin::dyld::Arch {
    if cfg!(target_arch = "aarch64") {
        sys::darwin::dyld::Arch::AArch64
    } else if cfg!(target_arch = "x86_64") {
        sys::darwin::dyld::Arch::X86_64
    } else {
        panic!("unsupported architecture");
    }
}
