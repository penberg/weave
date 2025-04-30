//! Platform-specific system interfaces.
//!
//! This module provides a unified interface to platform-specific functionality,
//! abstracting over differences between operating systems (Linux, macOS, etc.).
//!
//! The platform-specific implementations are conditionally compiled based on the
//! target OS, and common types are re-exported at the module level for easy access.

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

// Re-export platform-specific types as unified sys types
#[cfg(target_os = "macos")]
pub use darwin::{Task, TaskBuilder, execve, set_current_task};

#[cfg(target_os = "linux")]
pub use linux::{Task, TaskBuilder, execve, set_current_task};
