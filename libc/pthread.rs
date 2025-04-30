//! Pthread wrapper functions.
//!
//! These wrappers bypass the shared cache's pthread validation by calling
//! the host's pthread functions directly. The shared cache version validates
//! pthread structures using internal signatures, which can fail if the thread
//! wasn't created through the expected path.

use macros::weave_symbol;

/// Return the current thread's pthread_t.
///
/// This wrapper avoids the shared cache's pthread_self validation by calling
/// the host's pthread_self directly.
#[weave_symbol]
pub fn pthread_self() -> libc::pthread_t {
    unsafe { libc::pthread_self() }
}

/// Return the stack address for a pthread.
#[weave_symbol]
pub fn pthread_get_stackaddr_np(thread: libc::pthread_t) -> *mut libc::c_void {
    unsafe { libc::pthread_get_stackaddr_np(thread) }
}

/// Return the stack size for a pthread.
#[weave_symbol]
pub fn pthread_get_stacksize_np(thread: libc::pthread_t) -> libc::size_t {
    unsafe { libc::pthread_get_stacksize_np(thread) }
}

/// Initialize a mutex.
#[weave_symbol]
pub fn pthread_mutex_init(
    mutex: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> libc::c_int {
    unsafe { libc::pthread_mutex_init(mutex, attr) }
}

/// Destroy a mutex.
#[weave_symbol]
pub fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> libc::c_int {
    unsafe { libc::pthread_mutex_destroy(mutex) }
}

/// Lock a mutex.
#[weave_symbol]
pub fn pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int {
    unsafe { libc::pthread_mutex_lock(mutex) }
}

/// Unlock a mutex.
#[weave_symbol]
pub fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int {
    unsafe { libc::pthread_mutex_unlock(mutex) }
}

/// Try to lock a mutex.
#[weave_symbol]
pub fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int {
    unsafe { libc::pthread_mutex_trylock(mutex) }
}

/// Set thread name.
#[weave_symbol]
pub fn pthread_setname_np(name: *const libc::c_char) -> libc::c_int {
    unsafe { libc::pthread_setname_np(name) }
}

/// Get thread ID.
#[weave_symbol]
pub fn pthread_threadid_np(thread: libc::pthread_t, thread_id: *mut u64) -> libc::c_int {
    unsafe { libc::pthread_threadid_np(thread, thread_id) }
}
