/// Seeds the pseudo-random number generator.
///
/// # Arguments
///
/// * `seed` - Seed value
///
/// # Safety
///
/// This function is marked unsafe due to its C ABI compatibility.
///
/// # Library
///
/// Standard C library (libc, -lc)
#[unsafe(no_mangle)]
pub fn weave_srand(_seed: std::ffi::c_uint) {}

/// Generates a pseudo-random integer.
///
/// # Safety
///
/// This function is marked unsafe due to its C ABI compatibility.
///
/// # Library
///
/// Standard C library (libc, -lc)
#[unsafe(no_mangle)]
pub fn weave_rand() -> std::ffi::c_int {
    0
}
