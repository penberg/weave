//! Deterministic implementations of macOS libSystem functions.
//!
//! This module provides deterministic replacements for Darwin-specific
//! library functions that would otherwise introduce non-determinism.

use crate::runtime::random;
use macros::weave_symbol;

/// CCRNGStatus - return type for CommonCrypto RNG functions
pub type CCRNGStatus = i32;

/// kCCSuccess
const CC_SUCCESS: CCRNGStatus = 0;

/// Deterministic implementation of CCRandomGenerateBytes.
///
/// Instead of generating cryptographically secure random bytes,
/// this fills the buffer with deterministic pseudo-random bytes
/// from Weave's PRNG for reproducibility.
#[weave_symbol]
pub fn CCRandomGenerateBytes(bytes: *mut u8, count: usize) -> CCRNGStatus {
    if bytes.is_null() {
        return -1; // kCCParamError
    }

    // Fill with deterministic pseudo-random bytes
    let buf = unsafe { std::slice::from_raw_parts_mut(bytes, count) };
    random::fill_bytes(buf);

    CC_SUCCESS
}
