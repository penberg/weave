//! Deterministic time simulation for reproducible execution.
//!
//! This module provides a global time tick counter that advances with program
//! execution rather than wall-clock time. All time queries in Weave use this
//! counter to ensure deterministic, reproducible behavior.
//!
//! The initial time offset is derived from the seed, so different seeds
//! produce different (but deterministic) time values.

use super::random;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global time tick counter.
///
/// This counter is incremented on every dispatcher call (branch/jump),
/// providing a deterministic measure of program progress.
static TIME_TICK: AtomicU64 = AtomicU64::new(0);

/// Initialize the time system with a random offset derived from the PRNG.
///
/// This should be called once at startup, after random::init().
/// The initial offset is generated from the PRNG so different seeds
/// produce different starting times.
pub fn init() {
    // Generate initial time offset from PRNG
    // Use modulo to keep it within a reasonable range (about 50 years in microseconds)
    let offset = random::next_u64() % (50 * 365 * 24 * 60 * 60 * 1_000_000);
    TIME_TICK.store(offset, Ordering::SeqCst);
}

/// Advance the time tick counter by one.
///
/// Called by the dispatcher on every control flow transition.
pub fn tick() {
    TIME_TICK.fetch_add(1, Ordering::Release);
}

/// Get the current time tick value.
///
/// Returns a deterministic "time" value that advances with execution.
pub fn now() -> u64 {
    TIME_TICK.load(Ordering::Acquire)
}
