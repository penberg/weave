//! Malloc wrapper functions.
//!
//! These wrappers bypass the shared cache malloc by calling libc directly.

use macros::weave_symbol;

/// Allocate memory.
#[weave_symbol]
pub fn malloc(size: libc::size_t) -> *mut libc::c_void {
    unsafe { libc::malloc(size) }
}

/// Free memory.
#[weave_symbol]
pub fn free(ptr: *mut libc::c_void) {
    unsafe { libc::free(ptr) }
}

/// Allocate zeroed memory.
#[weave_symbol]
pub fn calloc(count: libc::size_t, size: libc::size_t) -> *mut libc::c_void {
    unsafe { libc::calloc(count, size) }
}

/// Reallocate memory.
#[weave_symbol]
pub fn realloc(ptr: *mut libc::c_void, size: libc::size_t) -> *mut libc::c_void {
    unsafe { libc::realloc(ptr, size) }
}

/// Allocate aligned memory.
#[weave_symbol]
pub fn posix_memalign(
    memptr: *mut *mut libc::c_void,
    alignment: libc::size_t,
    size: libc::size_t,
) -> libc::c_int {
    unsafe { libc::posix_memalign(memptr, alignment, size) }
}
