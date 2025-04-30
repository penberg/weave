use libc::{c_int, siginfo_t};
use std::process::exit;

/// # Safety
///
/// This function is called by the OS signal handling mechanism and must be marked
/// as unsafe because it:
/// - Dereferences raw pointers (`info`, `context`) provided by the OS
/// - Accesses signal context structures that may be in an inconsistent state
/// - Is called asynchronously and may interrupt the program at any point
pub unsafe extern "C" fn signal_handler(
    sig: c_int,
    info: *mut siginfo_t,
    context: *mut libc::c_void,
) {
    unsafe {
        eprintln!("A fatal error has been detected:");
        eprintln!("{} ({}) at {:p}", signal_name(sig), sig, (*info).si_addr());

        let ctx = context as *mut libc::ucontext_t;
        let mctx = &(*ctx).uc_mcontext;
        eprintln!(
            "rip={:p}, rsp={:p}, rbp={:p}",
            mctx.gregs[libc::REG_RIP as usize] as *const u8,
            mctx.gregs[libc::REG_RSP as usize] as *const u8,
            mctx.gregs[libc::REG_RBP as usize] as *const u8
        );
        eprintln!(
            "rax={:016p}  rbx={:016p}  rcx={:016p}  rdx={:016p}",
            mctx.gregs[libc::REG_RAX as usize] as *const u8,
            mctx.gregs[libc::REG_RBX as usize] as *const u8,
            mctx.gregs[libc::REG_RCX as usize] as *const u8,
            mctx.gregs[libc::REG_RDX as usize] as *const u8
        );
        eprintln!(
            "rsi={:016p}  rdi={:016p}  r8={:016p}   r9={:016p}",
            mctx.gregs[libc::REG_RSI as usize] as *const u8,
            mctx.gregs[libc::REG_RDI as usize] as *const u8,
            mctx.gregs[libc::REG_R8 as usize] as *const u8,
            mctx.gregs[libc::REG_R9 as usize] as *const u8
        );
        eprintln!(
            "r10={:016p}  r11={:016p}  r12={:016p}  r13={:016p}",
            mctx.gregs[libc::REG_R10 as usize] as *const u8,
            mctx.gregs[libc::REG_R11 as usize] as *const u8,
            mctx.gregs[libc::REG_R12 as usize] as *const u8,
            mctx.gregs[libc::REG_R13 as usize] as *const u8
        );
        eprintln!(
            "r14={:016p}  r15={:016p}",
            mctx.gregs[libc::REG_R14 as usize] as *const u8,
            mctx.gregs[libc::REG_R15 as usize] as *const u8
        );
        exit(1);
    }
}

fn signal_name(sig: c_int) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGILL => "SIGILL",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        _ => "UNKNOWN",
    }
}
