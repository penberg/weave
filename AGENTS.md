# Theory of Operation

## Overview

The purpose of this program is to run other programs with deterministic, repeatable behavior.

To run a guest program, you type:

```console
weave <program>
```

## Design

The supervisor loads the guest program and all its library dependencies into a dedicated guest address space. It then uses dynamic binary modification to translate the code, replacing non-deterministic execution with deterministic behavior. The CPU never executes original guest code directly—it only ever runs translated code from the code cache.

All executable code, including shared libraries, must be loaded into the guest address space and translated. This ensures that indirect branches, such as function pointer calls, always flow through the dispatcher rather than jumping to untranslated addresses.

### Loader

The supervisor implements its own executable loader rather than relying on the platform's dynamic linker. When loading a guest program, the supervisor parses the executable and maps its segments into a higher address range to prevent conflicts with supervisor memory. It then recursively loads all dependent libraries into the same guest address space and resolves dynamic symbols to point to these guest-loaded libraries.

This approach constrains the supervisor to supporting only position-independent executable (PIE) files.

### Execution

The supervisor translates code at the basic block granularity. A _basic block_ is a sequence of consecutive instructions with a single entry point, a single exit point, and no branches except possibly at the end.

When translating a basic block, the supervisor rewrites branch instructions to route through the dispatcher, rewrites system call instructions to call the supervisor's syscall handler, and copies deterministic instructions as-is. The translated block ends with an exit stub that saves guest CPU state and returns control to the dispatcher.

After translation, the supervisor jumps to the translated code, which executes natively. When the block reaches a control flow boundary, the exit stub executes and the dispatcher determines the next block to translate. This process continues indefinitely: supervisor → translated code → exit stub → dispatcher → next translated code.

### Determinism

Determinism is enforced at two levels. At the syscall level, all system calls flow through the supervisor's handler, which provides deterministic responses for time, random number generation, and I/O operations. At the instruction level, non-deterministic CPU instructions like timestamp counter reads and hardware random number generation are translated to return deterministic values.

## Testing

To test Weave, run the test suite with:

```console
make test
```
