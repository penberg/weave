use crate::runtime::{self, arm64::translate::translate_block};
use libc::{__darwin_arm_thread_state64, c_int, siginfo_t};
use std::process::exit;
use tracing::trace;

pub extern "C" fn signal_handler(sig: c_int, info: *mut siginfo_t, context: *mut libc::c_void) {
    unsafe {
        let ucontext = context as *mut libc::ucontext_t;
        let mctx = &mut *(*ucontext).uc_mcontext;
        let thread_state = std::mem::transmute::<
            &mut libc::__darwin_arm_thread_state64,
            &mut __darwin_arm_thread_state64,
        >(&mut mctx.__ss);

        let pc = thread_state.__pc;

        // Check if this is a callback from native code to guest code.
        // This happens when native library functions (like qsort) call function
        // pointers that point to guest code. Since guest code is mapped without
        // PROT_EXEC, this causes SIGBUS. We translate the guest code on demand
        // and resume execution at the translated address.
        if sig == libc::SIGBUS
            && let Some(exec_ctx) = try_get_execution_context() {
                let is_guest = pc >= exec_ctx.text_start && pc < exec_ctx.text_end;
                if is_guest {
                    trace!(
                        "Signal handler: translating callback at guest 0x{:016x}",
                        pc
                    );

                    // Translate the guest code at PC
                    match translate_block(exec_ctx, pc, exec_ctx.text_end, false) {
                        Ok(block) => {
                            // Update PC to point to translated code (skip 8-byte header)
                            let translated_addr = block.text_start().add(8) as u64;
                            trace!(
                                "Signal handler: resuming at translated 0x{:016x}",
                                translated_addr
                            );
                            thread_state.__pc = translated_addr;
                            // Return from signal handler - kernel will resume at translated code
                            return;
                        }
                        Err(e) => {
                            eprintln!("Failed to translate callback at 0x{:016x}: {}", pc, e);
                        }
                    }
                }
            }

        // Fatal error - print diagnostics and exit
        eprintln!("A fatal error has been detected:");
        eprintln!("{} ({}) at {:p}", signal_name(sig), sig, (*info).si_addr);
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

/// Try to get the execution context. Returns None if not available.
/// This is safe to call from a signal handler on the same thread.
fn try_get_execution_context() -> Option<&'static mut runtime::ExecutionContext> {
    // Use the thread-local storage to get the context
    // This is safe because signal handlers run on the same thread
    runtime::try_get_current_context()
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
