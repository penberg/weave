//! Deterministic time functions.

#![allow(non_camel_case_types)]

use crate::runtime::time;
use macros::weave_symbol;

/// Time in seconds.
pub type time_t = std::os::raw::c_long;

/// Suseconds (microseconds) type.
pub type suseconds_t = std::os::raw::c_long;

/// Time value with seconds and microseconds.
#[repr(C)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

/// Time specification with seconds and nanoseconds.
#[repr(C)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: std::os::raw::c_long,
}

/// Timezone (unused but required for gettimeofday signature).
#[repr(C)]
pub struct timezone {
    pub tz_minuteswest: std::os::raw::c_int,
    pub tz_dsttime: std::os::raw::c_int,
}

/// Convert tick count to seconds and nanoseconds.
///
/// We treat each tick as 1 microsecond of virtual time,
/// starting from a fixed epoch (2000-01-01 00:00:00 UTC).
fn tick_to_time() -> (time_t, i64) {
    let ticks = time::now();
    // Base epoch: 2000-01-01 00:00:00 UTC = 946684800 seconds since Unix epoch
    const EPOCH_2000: i64 = 946684800;
    // Each tick = 1 microsecond = 1000 nanoseconds
    let extra_secs = (ticks / 1_000_000) as i64;
    let nanos = ((ticks % 1_000_000) * 1000) as i64;
    ((EPOCH_2000 + extra_secs) as time_t, nanos)
}

/// Clock IDs for clock_gettime.
pub const CLOCK_REALTIME: std::os::raw::c_int = 0;
pub const CLOCK_MONOTONIC: std::os::raw::c_int = 6; // macOS value

/// Get time in seconds.
#[weave_symbol]
pub fn time(_tloc: *mut time_t) -> time_t {
    let (secs, _) = tick_to_time();
    secs
}

/// Get time of day.
#[weave_symbol]
pub fn gettimeofday(tv: *mut timeval, tz: *mut timezone) -> std::os::raw::c_int {
    if !tv.is_null() {
        let (secs, nanos) = tick_to_time();
        unsafe {
            (*tv).tv_sec = secs;
            (*tv).tv_usec = (nanos / 1000) as suseconds_t; // Convert nanos to micros
        }
    }
    if !tz.is_null() {
        unsafe {
            (*tz).tz_minuteswest = 0;
            (*tz).tz_dsttime = 0;
        }
    }
    0 // Success
}

/// Get clock time.
#[weave_symbol]
pub fn clock_gettime(_clock_id: std::os::raw::c_int, tp: *mut timespec) -> std::os::raw::c_int {
    if tp.is_null() {
        return -1;
    }
    let (secs, nanos) = tick_to_time();
    unsafe {
        (*tp).tv_sec = secs;
        (*tp).tv_nsec = nanos as std::os::raw::c_long;
    }
    0 // Success
}
