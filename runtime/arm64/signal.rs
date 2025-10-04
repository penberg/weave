use libc::{__darwin_arm_thread_state64, c_int, siginfo_t};
use std::process::exit;

pub extern "C" fn signal_handler(sig: c_int, info: *mut siginfo_t, context: *mut libc::c_void) {
    eprintln!("A fatal error has been detected:");
    unsafe {
        eprintln!("{} ({}) at {:p}", signal_name(sig), sig, (*info).si_addr);

        let ctx = context as *mut libc::ucontext_t;
        let mctx = &(*ctx).uc_mcontext;
        let mctx = &*(*mctx);
        let thread_state = std::mem::transmute::<
            &libc::__darwin_arm_thread_state64,
            &__darwin_arm_thread_state64,
        >(&mctx.__ss);
        eprintln!(
            "pc={:p}, sp={:p}, fp={:p}, lr={:p}",
            thread_state.__pc as *const u8,
            thread_state.__sp as *const u8,
            thread_state.__fp as *const u8,
            thread_state.__lr as *const u8
        );
        eprintln!(
            "x0:  {:016p}  x1:  {:016p}  x2:  {:016p}  x3:  {:016p}",
            thread_state.__x[0] as *const u8,
            thread_state.__x[1] as *const u8,
            thread_state.__x[2] as *const u8,
            thread_state.__x[3] as *const u8
        );
        eprintln!(
            "x4:  {:016p}  x5:  {:016p}  x6:  {:016p}  x7:  {:016p}",
            thread_state.__x[4] as *const u8,
            thread_state.__x[5] as *const u8,
            thread_state.__x[6] as *const u8,
            thread_state.__x[7] as *const u8
        );
        eprintln!(
            "x8:  {:016p}  x9:  {:016p}  x10: {:016p}  x11: {:016p}",
            thread_state.__x[8] as *const u8,
            thread_state.__x[9] as *const u8,
            thread_state.__x[10] as *const u8,
            thread_state.__x[11] as *const u8
        );
        eprintln!(
            "x12: {:016p}  x13: {:016p}  x14: {:016p}  x15: {:016p}",
            thread_state.__x[12] as *const u8,
            thread_state.__x[13] as *const u8,
            thread_state.__x[14] as *const u8,
            thread_state.__x[15] as *const u8
        );
        eprintln!(
            "x16: {:016p}  x17: {:016p}  x18: {:016p}  x19: {:016p}",
            thread_state.__x[16] as *const u8,
            thread_state.__x[17] as *const u8,
            thread_state.__x[18] as *const u8,
            thread_state.__x[19] as *const u8
        );
        eprintln!(
            "x20: {:016p}  x21: {:016p}  x22: {:016p}  x23: {:016p}",
            thread_state.__x[20] as *const u8,
            thread_state.__x[21] as *const u8,
            thread_state.__x[22] as *const u8,
            thread_state.__x[23] as *const u8
        );
        eprintln!(
            "x24: {:016p}  x25: {:016p}  x26: {:016p}  x27: {:016p}",
            thread_state.__x[24] as *const u8,
            thread_state.__x[25] as *const u8,
            thread_state.__x[26] as *const u8,
            thread_state.__x[27] as *const u8
        );
        eprintln!("x28: {:016p}", thread_state.__x[28] as *const u8);
    }
    exit(1);
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
