#[cfg(target_os = "macos")]
pub mod darwin;

pub mod libc;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod mmap;
pub mod runtime;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("instruction decode error: {0}")]
    InstructionDecodeError(String),
}

pub type Result<T> = core::result::Result<T, Error>;

pub use mmap::MappedFile;

pub use runtime::{CpuState, ExecutionContext};

/// Probe the host architecture
#[cfg(target_os = "macos")]
pub fn probe_host_arch() -> darwin::dyld::Arch {
    if cfg!(target_arch = "aarch64") {
        darwin::dyld::Arch::AArch64
    } else if cfg!(target_arch = "x86_64") {
        darwin::dyld::Arch::X86_64
    } else {
        panic!("unsupported architecture");
    }
}
