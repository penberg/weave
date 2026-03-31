//! String/memory function wrappers.
//!
//! These redirect guest string and memory functions to the host libc,
//! bypassing IFUNC-resolved optimized implementations in guest libc
//! that may use instructions the translator does not yet support.

use macros::weave_symbol;

#[weave_symbol]
pub fn strcmp(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int {
    unsafe { libc::strcmp(s1, s2) }
}

#[weave_symbol]
pub fn strncmp(s1: *const libc::c_char, s2: *const libc::c_char, n: libc::size_t) -> libc::c_int {
    unsafe { libc::strncmp(s1, s2, n) }
}

#[weave_symbol]
pub fn strlen(s: *const libc::c_char) -> libc::size_t {
    unsafe { libc::strlen(s) }
}

#[weave_symbol]
pub fn strcpy(dst: *mut libc::c_char, src: *const libc::c_char) -> *mut libc::c_char {
    unsafe { libc::strcpy(dst, src) }
}

#[weave_symbol]
pub fn strncpy(
    dst: *mut libc::c_char,
    src: *const libc::c_char,
    n: libc::size_t,
) -> *mut libc::c_char {
    unsafe { libc::strncpy(dst, src, n) }
}

#[weave_symbol]
pub fn memcpy(
    dst: *mut libc::c_void,
    src: *const libc::c_void,
    n: libc::size_t,
) -> *mut libc::c_void {
    unsafe { libc::memcpy(dst, src, n) }
}

#[weave_symbol]
pub fn memmove(
    dst: *mut libc::c_void,
    src: *const libc::c_void,
    n: libc::size_t,
) -> *mut libc::c_void {
    unsafe { libc::memmove(dst, src, n) }
}

#[weave_symbol]
pub fn memset(s: *mut libc::c_void, c: libc::c_int, n: libc::size_t) -> *mut libc::c_void {
    unsafe { libc::memset(s, c, n) }
}

#[weave_symbol]
pub fn memcmp(
    s1: *const libc::c_void,
    s2: *const libc::c_void,
    n: libc::size_t,
) -> libc::c_int {
    unsafe { libc::memcmp(s1, s2, n) }
}
