use libc::{SIGBUS, SIGFPE, SIGILL, SIGSEGV};
use std::{env, process::exit};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "macos")]
use weave::darwin::{Task, TaskBuilder, execve, set_current_task};

#[cfg(target_os = "linux")]
use weave::linux::{Task, TaskBuilder, execve, set_current_task};

use weave::runtime::arch::signal::signal_handler;

struct Opts {
    /// Whether to print the code.
    print_code: bool,

    /// The program to run.
    program: String,

    /// The arguments to pass to the program.
    _program_args: Vec<String>,
}

fn main() {
    setup_logging();

    register_signal_handlers();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: weave [options] -- <program> [arguments...]");
        exit(1);
    }
    let opts = parse_opts(&args);

    let mut task = TaskBuilder::new();
    if opts.print_code {
        task = task.print_code(true);
    }
    let mut task = task.build();
    set_current_task(&mut task as *mut Task);

    execve(&opts.program);
}

fn register_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;

        libc::sigaction(SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(SIGILL, &sa, std::ptr::null_mut());
        libc::sigaction(SIGBUS, &sa, std::ptr::null_mut());
        libc::sigaction(SIGFPE, &sa, std::ptr::null_mut());
    }
}

fn parse_opts(args: &[String]) -> Opts {
    let mut print_code = false;
    let mut program = String::new();
    let mut program_args: Vec<String> = Vec::new();
    let mut i = 1; // Skip program name
    while i < args.len() {
        if args[i] == "--print-code" {
            print_code = true;
            i += 1;
        } else if args[i] == "--" {
            if i + 1 < args.len() {
                program = args[i + 1].clone();
                program_args = args[i + 2..].to_vec();
            }
            break;
        } else if program.is_empty() {
            // If we haven't found a program yet and this isn't an option, treat it as the program
            program = args[i].clone();
            program_args = args[i + 1..].to_vec();
            break;
        } else {
            i += 1;
        }
    }
    Opts {
        print_code,
        program,
        _program_args: program_args,
    }
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}
