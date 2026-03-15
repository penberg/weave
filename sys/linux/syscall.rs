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
const SYS_SYSINFO: i64 = 99;
const SYS_SCHED_GETAFFINITY: i64 = 204;
const SYS_PRCTL: i64 = 157;
const SYS_ARCH_PRCTL: i64 = 158;
const SYS_SET_TID_ADDRESS: i64 = 218;
const SYS_SET_ROBUST_LIST: i64 = 273;
const SYS_PRLIMIT64: i64 = 302;
const SYS_GETRANDOM: i64 = 318;

static mut THREAD_NAME: [u8; 16] = [0u8; 16];

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
    arg4: u64,
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
        SYS_SYSINFO => {
            let si = arg1 as *mut libc::sysinfo;
            let uptime = crate::runtime::time::now() / 1_000_000; // ticks → seconds
            unsafe {
                std::ptr::write_bytes(si, 0, 1);
                (*si).uptime = uptime as libc::c_long;
                (*si).totalram = 8 * 1024 * 1024 * 1024; // 8 GB
                (*si).freeram = 4 * 1024 * 1024 * 1024;
                (*si).procs = 1;
                (*si).mem_unit = 1;
            }
            0
        }
        SYS_SCHED_GETAFFINITY => {
            let cpusetsize = arg2 as usize;
            let mask = arg3 as *mut u8;
            unsafe {
                std::ptr::write_bytes(mask, 0, cpusetsize);
                *mask = 1; // CPU 0 only
            }
            8 // size of cpumask in bytes
        }
        SYS_PRLIMIT64 => {
            // arg1 = pid (0 = self), arg2 = resource, arg3 = new_limit, arg4 = old_limit
            let old_limit = arg4 as *mut libc::rlimit;
            if !old_limit.is_null() {
                let (cur, max): (u64, u64) = match arg2 {
                    3 => (8 * 1024 * 1024, u64::MAX),   // RLIMIT_STACK: 8 MB
                    7 => (1024, 1024 * 1024),            // RLIMIT_NOFILE: 1024
                    _ => (u64::MAX, u64::MAX),
                };
                unsafe {
                    (*old_limit).rlim_cur = cur;
                    (*old_limit).rlim_max = max;
                }
            }
            0
        }
        SYS_PRCTL => {
            const PR_SET_NAME: u64 = 15;
            const PR_GET_NAME: u64 = 16;
            match arg1 {
                PR_SET_NAME => {
                    let name = arg2 as *const u8;
                    unsafe {
                        let dst = std::ptr::addr_of_mut!(THREAD_NAME) as *mut u8;
                        std::ptr::write_bytes(dst, 0, 16);
                        for i in 0..15 {
                            let c = *name.add(i);
                            if c == 0 { break; }
                            *dst.add(i) = c;
                        }
                    }
                    0
                }
                PR_GET_NAME => {
                    let buf = arg2 as *mut u8;
                    unsafe {
                        let src = std::ptr::addr_of!(THREAD_NAME) as *const u8;
                        std::ptr::copy_nonoverlapping(src, buf, 16);
                    }
                    0
                }
                _ => -libc::EINVAL as libc::c_long,
            }
        }
        SYS_ARCH_PRCTL => {
            const ARCH_SET_FS: u64 = 0x1002;
            const ARCH_GET_FS: u64 = 0x1003;
            match arg1 {
                ARCH_SET_FS => {
                    unsafe { super::kernel::GUEST_FS_BASE = arg2 };
                    0
                }
                ARCH_GET_FS => {
                    let ptr = arg2 as *mut u64;
                    let mut fs_base = unsafe { super::kernel::GUEST_FS_BASE };
                    if fs_base == 0 {
                        // No TLS set up yet — allocate a minimal TCB with a
                        // self-pointer so fs:0 reads work.
                        let tcb = unsafe {
                            libc::mmap(
                                std::ptr::null_mut(),
                                4096,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                                -1,
                                0,
                            )
                        };
                        if tcb != libc::MAP_FAILED {
                            let addr = tcb as u64;
                            unsafe {
                                *(tcb as *mut u64) = addr;
                                super::kernel::GUEST_FS_BASE = addr;
                            }
                            fs_base = addr;
                        }
                    }
                    unsafe { *ptr = fs_base };
                    0
                }
                _ => -libc::EINVAL as libc::c_long,
            }
        }
        SYS_SET_TID_ADDRESS => 1000, // deterministic TID
        SYS_SET_ROBUST_LIST => 0,   // no-op for single-threaded
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
