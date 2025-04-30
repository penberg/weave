//! Symbol registration and lookup for Weave libc overrides.
//!
//! This module provides a distributed slice that collects all symbols
//! registered via the `#[weave_symbol]` attribute macro.

use linkme::distributed_slice;

/// A function pointer wrapper that's Sync.
///
/// Function pointers are safe to share across threads (they're just addresses
/// into read-only code), but Rust doesn't automatically implement Sync for
/// raw pointers.
#[derive(Clone, Copy)]
pub struct FnPtr(pub *const ());

// SAFETY: Function pointers point to immutable code, so they're safe to share.
unsafe impl Sync for FnPtr {}

/// Distributed slice of Weave symbol mappings.
///
/// Each entry maps a C symbol name (e.g., "_dlopen") to its Weave
/// implementation function pointer.
#[distributed_slice]
pub static WEAVE_SYMBOLS: [(&str, FnPtr)] = [..];

/// Look up a Weave symbol override by name.
///
/// Returns the function address if found, or None if the symbol
/// is not overridden by Weave.
pub fn lookup(symbol_name: &str) -> Option<u64> {
    WEAVE_SYMBOLS
        .iter()
        .find(|(name, _)| *name == symbol_name)
        .map(|(_, ptr)| ptr.0 as u64)
}
