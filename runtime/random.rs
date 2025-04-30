//! Deterministic pseudo-random number generator for reproducible execution.
//!
//! This module provides a global PRNG that can be seeded at startup via the
//! `--seed` command line option. All random number generation in Weave uses
//! this PRNG to ensure deterministic, reproducible behavior.

use std::sync::atomic::{AtomicU64, Ordering};

/// Default seed value for deterministic execution
pub const DEFAULT_SEED: u64 = 0x853c49e6748fea9b;

/// Global PRNG state using xorshift64
static PRNG_STATE: AtomicU64 = AtomicU64::new(DEFAULT_SEED);

/// Initialize the PRNG with a seed value.
/// This should be called once at startup.
///
/// # Panics
/// Panics if seed is zero (xorshift requires non-zero state).
pub fn init(seed: u64) {
    assert!(seed != 0, "PRNG seed must be non-zero");
    PRNG_STATE.store(seed, Ordering::SeqCst);
}

/// Generate the next pseudo-random u64 value.
/// Uses xorshift64 algorithm for fast, deterministic generation.
pub fn next_u64() -> u64 {
    loop {
        let state = PRNG_STATE.load(Ordering::SeqCst);
        let mut x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if PRNG_STATE
            .compare_exchange(state, x, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return x;
        }
    }
}

/// Generate a pseudo-random i32 value (for C rand() compatibility).
pub fn next_i32() -> i32 {
    (next_u64() & 0x7FFFFFFF) as i32
}

/// Fill a buffer with pseudo-random bytes.
pub fn fill_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let val = next_u64();
        let bytes = val.to_le_bytes();
        for b in bytes {
            if i >= buf.len() {
                break;
            }
            buf[i] = b;
            i += 1;
        }
    }
}
