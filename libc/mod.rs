//! Deterministic libc function implementations.
//!
//! This module provides deterministic implementations of standard C library functions
//! for use in reproducible execution environments. All functions return predictable
//! values rather than system-dependent results.
//!
//! # Modules
//!
//! * [`rand`] - Pseudo-random number generation functions
//! * [`time`] - Time-related functions
//! * [`darwin`] - macOS/Darwin-specific functions (libSystem)

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "macos")]
pub mod dlfcn;
pub mod malloc;
#[cfg(target_os = "macos")]
pub mod pthread;
pub mod rand;
pub mod time;
