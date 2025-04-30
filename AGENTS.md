# Theory of Operation

## Overview

The purpose of this program is to run other programs with deterministic, repeatable behavior.

The core of the program is a _supervisor_, which is essentially a userspace operating system and support libraries, such as the C standard library, with a binary translator for executing _guest programs_. 

To run a guest program, you type:

```console
weave <program>
```

## Design

The supervisor starts by loading the guest program, a binary executable in Mach-O object format, into the supervisor's memory space using the `execve()` function. The `execve()` function emulates both the `execve()` system call and a dynamic linker to load the program. When the guest program is loaded, the supervisor translates the first basic block of the guest program into using dynamic binary modification with the purpose of replacing non-deterministic execution with deterministic one. For example, the supervisor translates system call invocation instruction into a call to the supervisor code, which provides deterministic execution. Instructions that are already deterministic are executed as-is, except for branches, which need to be mapped to the translated code addresses.

### Loader

To execute a guest program, the supervisor loads the program executable into the same address space as the supervisor itself. The supervisor parses the guest program's Mach-O object format executable and maps its segments into memory. To prevent conflicts with supervisor's own memory, the supervisor loads the guest program into a higher address range. Please note that this approach constraints supervisor to only supporting position-independent executable (PIE) files. Non-PIE executables are currently not supported.

### Execution

To execute a guest program, the supervisor scans the program, starting at its entry point, and translates the code at the basic block granularity. A _basic block_ is a sequence of consecutive instructions in a program that has a single entry point, a single exit point, and no branches except possibly at the end. 

When translating a basic block, the supervisor generates _exit stubs_ for every branch path that return control back to the supervisor. These exit stubs save the complete guest CPU state (including all general-purpose registers and processor flags) and call the supervisor's dispatcher with metadata about the executed path, including the application address, basic block identifier, and the reason for exit (branch target or system call).

After translating a basic block, the supervisor jumps directly to the translated code, which executes natively on the CPU. Control never returns to the supervisor through normal execution flow - instead, when the translated block reaches a control flow instruction (branch, system call, etc.), the corresponding exit stub executes. The exit stub saves all guest register state to memory and calls the supervisor's dispatcher function with information about why execution stopped and where to continue.

The dispatcher then determines the next basic block to execute based on the exit stub information, translates it on demand if necessary, and jumps directly to the newly translated block. This process continues indefinitely, with control flowing from supervisor → guest code → exit stub → dispatcher → next guest code, eliminating traditional context switching overhead.

## Testing

To test Weave, run the test suite with:

```console
make test
```
