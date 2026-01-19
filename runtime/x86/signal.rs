use crate::runtime::{self, x86::translate::translate_block};
use libc::{c_int, siginfo_t};
use std::process::exit;
use tracing::trace;

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
        let ctx = context as *mut libc::ucontext_t;
        let mctx = &mut (*ctx).uc_mcontext;
        let pc = mctx.gregs[libc::REG_RIP as usize] as u64;

        // Check if this is a callback from native code to guest code.
        // This happens when native library functions (like qsort) call function
        // pointers that point to guest code. Since guest code is mapped without
        // PROT_EXEC, this causes SIGSEGV. We translate the guest code on demand
        // and resume execution at the translated address.
        if sig == libc::SIGSEGV {
            if let Some(exec_ctx) = try_get_execution_context() {
                let is_guest = pc >= exec_ctx.text_start && pc < exec_ctx.text_end;
                if is_guest {
                    trace!(
                        "Signal handler: translating callback at guest 0x{:016x}",
                        pc
                    );

                    match translate_block(exec_ctx, pc, exec_ctx.text_end, false) {
                        Ok(block) => {
                            let translated_addr = block.text_start().add(8) as u64;
                            trace!(
                                "Signal handler: resuming at translated 0x{:016x}",
                                translated_addr
                            );
                            mctx.gregs[libc::REG_RIP as usize] = translated_addr as i64;
                            return;
                        }
                        Err(e) => {
                            eprintln!("Failed to translate callback at 0x{:016x}: {}", pc, e);
                        }
                    }
                }
            }
        }

        // Fatal error - print diagnostics and exit
        eprintln!("A fatal error has been detected:");
        eprintln!("{} ({}) at {:p}", signal_name(sig), sig, (*info).si_addr());

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

/// Try to get the execution context. Returns None if not available.
/// This is safe to call from a signal handler on the same thread.
fn try_get_execution_context() -> Option<&'static mut runtime::ExecutionContext> {
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
