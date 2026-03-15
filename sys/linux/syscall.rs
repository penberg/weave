//! Deterministic syscall wrapper.
//!
//! Intercepts the libc `syscall()` function so that guest code calling
//! `syscall(SYS_futex, ...)` or similar goes through the supervisor
//! instead of issuing real kernel syscalls.

use macros::weave_symbol;
use tracing::trace;

const SYS_EXIT: i64 = 60;
const SYS_FUTEX: i64 = 202;
const SYS_EXIT_GROUP: i64 = 231;
const SYS_GETRANDOM: i64 = 318;

const FUTEX_PRIVATE_FLAG: i32 = 128;
const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_WAIT_BITSET: i32 = 9;

#[weave_symbol]
pub fn syscall(
    number: libc::c_long,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> libc::c_long {
    trace!("syscall wrapper: number={}", number);
    match number as i64 {
        SYS_EXIT | SYS_EXIT_GROUP => {
            trace!("syscall: exit/exit_group({})", arg1 as i32);
            std::process::exit(arg1 as i32);
        }
        SYS_FUTEX => {
            let op = (arg2 as i32) & !FUTEX_PRIVATE_FLAG;
            match op {
                FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                    // Single-threaded deterministic execution:
                    // Check if *addr == val. If not, return EAGAIN.
                    // If equal, force the value to 0 (simulating an unlock by
                    // another thread) so the caller's retry loop observes a
                    // changed value and makes progress instead of spinning.
                    let addr = arg1 as *mut u32;
                    let val = arg3 as u32;
                    let current = unsafe { std::ptr::read_volatile(addr) };
                    trace!(
                        "syscall: futex_wait(addr=0x{:x}, val={}, current={})",
                        arg1, val, current
                    );
                    if current != val {
                        return -libc::EAGAIN as libc::c_long;
                    }
                    unsafe { std::ptr::write_volatile(addr, 0) };
                    0
                }
                FUTEX_WAKE => {
                    // No threads to wake in single-threaded mode
                    trace!("syscall: futex_wake(addr=0x{:x})", arg1);
                    0
                }
                _ => {
                    todo!("unsupported futex operation: 0x{:x}", arg2);
                }
            }
        }
        SYS_GETRANDOM => {
            let buf = arg1 as *mut u8;
            let len = arg2 as usize;
            let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
            crate::runtime::random::fill_bytes(slice);
            len as libc::c_long
        }
        _ => {
            todo!("unsupported syscall via libc wrapper: {}", number);
        }
    }
}
