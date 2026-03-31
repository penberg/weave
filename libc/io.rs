//! I/O wrapper functions.
//!
//! These wrappers redirect guest stdio calls to the host, bypassing
//! guest libc's FILE* structures which require complex TLS setup.

use macros::weave_symbol;

#[weave_symbol]
pub fn puts(s: *const libc::c_char) -> libc::c_int {
    unsafe { libc::puts(s) }
}

// Register host libc's printf/fprintf directly as weave symbols.
// These are variadic C functions that can't be wrapped with #[weave_symbol],
// so we register the host function pointers directly.
unsafe extern "C" {
    fn printf(fmt: *const libc::c_char, ...) -> libc::c_int;
    fn fprintf(stream: *mut libc::FILE, fmt: *const libc::c_char, ...) -> libc::c_int;
    fn sprintf(buf: *mut libc::c_char, fmt: *const libc::c_char, ...) -> libc::c_int;
    fn snprintf(
        buf: *mut libc::c_char,
        size: libc::size_t,
        fmt: *const libc::c_char,
        ...
    ) -> libc::c_int;
    fn sscanf(s: *const libc::c_char, fmt: *const libc::c_char, ...) -> libc::c_int;
    // setjmp/longjmp must be registered as direct pointers (not wrappers)
    // because setjmp needs to save the caller's frame, not a wrapper's frame.
    fn _setjmp(env: *mut libc::c_void) -> libc::c_int;
    fn longjmp(env: *mut libc::c_void, val: libc::c_int);
    fn __sigsetjmp(env: *mut libc::c_void, savemask: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut libc::c_void, val: libc::c_int);
}

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_PRINTF: (&str, crate::symbols::FnPtr) =
    ("_printf", crate::symbols::FnPtr(printf as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_FPRINTF: (&str, crate::symbols::FnPtr) =
    ("_fprintf", crate::symbols::FnPtr(fprintf as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SPRINTF: (&str, crate::symbols::FnPtr) =
    ("_sprintf", crate::symbols::FnPtr(sprintf as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SNPRINTF: (&str, crate::symbols::FnPtr) =
    ("_snprintf", crate::symbols::FnPtr(snprintf as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SSCANF: (&str, crate::symbols::FnPtr) =
    ("_sscanf", crate::symbols::FnPtr(sscanf as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SETJMP: (&str, crate::symbols::FnPtr) =
    ("__setjmp", crate::symbols::FnPtr(_setjmp as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_LONGJMP: (&str, crate::symbols::FnPtr) =
    ("_longjmp", crate::symbols::FnPtr(longjmp as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SIGSETJMP: (&str, crate::symbols::FnPtr) =
    ("___sigsetjmp", crate::symbols::FnPtr(__sigsetjmp as *const ()));

#[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
static _WEAVE_SYM_SIGLONGJMP: (&str, crate::symbols::FnPtr) =
    ("_siglongjmp", crate::symbols::FnPtr(siglongjmp as *const ()));

#[weave_symbol]
pub fn write(fd: libc::c_int, buf: *const libc::c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe { libc::write(fd, buf, count) }
}

#[weave_symbol]
pub fn read(fd: libc::c_int, buf: *mut libc::c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe { libc::read(fd, buf, count) }
}

#[weave_symbol]
pub fn fwrite(
    ptr: *const libc::c_void,
    size: libc::size_t,
    nmemb: libc::size_t,
    stream: *mut libc::FILE,
) -> libc::size_t {
    unsafe { libc::fwrite(ptr, size, nmemb, stream) }
}

#[weave_symbol]
pub fn fread(
    ptr: *mut libc::c_void,
    size: libc::size_t,
    nmemb: libc::size_t,
    stream: *mut libc::FILE,
) -> libc::size_t {
    unsafe { libc::fread(ptr, size, nmemb, stream) }
}

#[weave_symbol]
pub fn fflush(stream: *mut libc::FILE) -> libc::c_int {
    unsafe { libc::fflush(stream) }
}

#[weave_symbol]
pub fn fclose(stream: *mut libc::FILE) -> libc::c_int {
    unsafe { libc::fclose(stream) }
}

#[weave_symbol]
pub fn fopen(path: *const libc::c_char, mode: *const libc::c_char) -> *mut libc::FILE {
    unsafe { libc::fopen(path, mode) }
}

#[weave_symbol]
pub fn fgets(
    buf: *mut libc::c_char,
    size: libc::c_int,
    stream: *mut libc::FILE,
) -> *mut libc::c_char {
    unsafe { libc::fgets(buf, size, stream) }
}

#[weave_symbol]
pub fn fputs_unlocked(s: *const libc::c_char, stream: *mut libc::FILE) -> libc::c_int {
    unsafe { libc::fputs(s, stream) }
}

#[weave_symbol]
pub fn fputc(c: libc::c_int, stream: *mut libc::FILE) -> libc::c_int {
    unsafe { libc::fputc(c, stream) }
}

#[weave_symbol]
pub fn vfprintf(
    stream: *mut libc::FILE,
    fmt: *const libc::c_char,
    ap: *mut libc::c_void,
) -> libc::c_int {
    // va_list is passed as opaque pointer; delegate to host libc
    unsafe extern "C" {
        fn vfprintf(
            stream: *mut libc::FILE,
            fmt: *const libc::c_char,
            ap: *mut libc::c_void,
        ) -> libc::c_int;
    }
    unsafe { vfprintf(stream, fmt, ap) }
}

#[weave_symbol]
pub fn vsprintf(
    buf: *mut libc::c_char,
    fmt: *const libc::c_char,
    ap: *mut libc::c_void,
) -> libc::c_int {
    unsafe extern "C" {
        fn vsprintf(
            buf: *mut libc::c_char,
            fmt: *const libc::c_char,
            ap: *mut libc::c_void,
        ) -> libc::c_int;
    }
    unsafe { vsprintf(buf, fmt, ap) }
}

#[weave_symbol]
pub fn vsnprintf(
    buf: *mut libc::c_char,
    size: libc::size_t,
    fmt: *const libc::c_char,
    ap: *mut libc::c_void,
) -> libc::c_int {
    unsafe extern "C" {
        fn vsnprintf(
            buf: *mut libc::c_char,
            size: libc::size_t,
            fmt: *const libc::c_char,
            ap: *mut libc::c_void,
        ) -> libc::c_int;
    }
    unsafe { vsnprintf(buf, size, fmt, ap) }
}
