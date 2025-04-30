//! Deterministic random number generation.

use crate::runtime::random;
use macros::weave_symbol;

/// Seeds the pseudo-random number generator.
///
/// Note: This is a no-op in Weave. The seed is controlled by the
/// deterministic random generation subsystem.
#[weave_symbol]
pub fn srand(_seed: std::ffi::c_uint) {
    // Intentionally ignored - seed is controlled by the deterministic random subsystem
}

/// Generates a pseudo-random integer.
#[weave_symbol]
pub fn rand() -> std::ffi::c_int {
    random::next_i32()
}
