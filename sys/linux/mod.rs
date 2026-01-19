//! Linux-specific system interfaces.
//!
//! This module provides Linux-specific implementations for process execution,
//! ELF binary loading, dynamic linking, and C library function interception.
//!
//! # Submodules
//!
//! - [`elf`] - ELF binary parsing and loading
//! - [`glibc`] - glibc function implementations for dynamically linked binaries
//! - [`kernel`] - Linux process and task management
//! - [`ld_linux`] - Dynamic linker implementation (similar to ld-linux.so)

pub mod elf;
pub mod glibc;
pub mod kernel;
pub mod ld_linux;
pub mod syscall;

pub use kernel::{Task, TaskBuilder, execve, get_current_task, set_current_task};
