#![allow(non_camel_case_types)]

use crate::runtime::arm64::TIME_TICK;
use std::sync::atomic::Ordering;

/// Time in seconds.
pub type time_t = std::os::raw::c_long;

/// Get time in seconds.
///
/// # Safety
///
/// This function is marked unsafe due to its C ABI compatibility.
///
/// Library:
///
/// Standard C library (libc, -lc)
#[unsafe(no_mangle)]
pub unsafe fn weave_time(_tloc: *mut time_t) -> time_t {
    TIME_TICK.load(Ordering::Acquire) as time_t
}
