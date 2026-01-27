//! Dynamic loading (dlfcn) wrappers.
//!
//! These thin wrappers call into the dyld implementation to load libraries
//! into guest address space and prepare them for binary translation.

use macros::weave_symbol;

/// Load a dynamic library for execution under Weave.
///
/// This loads the library into guest address space and prepares it for
/// binary translation.
///
/// Returns a handle (the library's base address) or null on failure.
#[weave_symbol]
pub fn dlopen(path: *const libc::c_char, flags: libc::c_int) -> *mut libc::c_void {
    crate::sys::darwin::dyld::dlopen(path, flags)
}

/// Look up a symbol in a dynamically loaded library.
#[weave_symbol]
pub fn dlsym(handle: *mut libc::c_void, symbol: *const libc::c_char) -> *mut libc::c_void {
    crate::sys::darwin::dyld::dlsym(handle, symbol)
}

/// Close a dynamically loaded library.
#[weave_symbol]
pub fn dlclose(handle: *mut libc::c_void) -> libc::c_int {
    crate::sys::darwin::dyld::dlclose(handle)
}

/// Return error message for last dlopen/dlsym/dlclose error.
#[weave_symbol]
pub fn dlerror() -> *mut libc::c_char {
    crate::sys::darwin::dyld::dlerror()
}
