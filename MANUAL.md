# Weave User Manual

## Overview

Weave is a deterministic execution tool that eliminates non-deterministic bugs by controlling all sources of randomness in program execution. It provides perfect reproducibility for debugging hard-to-reproduce bugs.

## Usage

Run programs with Weave using the following syntax:

```bash
weave <program> [arguments...]
```

Or with explicit argument separation:

```bash
weave [options] -- <program> [arguments...]
```

### Examples

Run a simple program:
```bash
weave ./myprogram
```

Run a program with arguments:
```bash
weave ./myprogram arg1 arg2
```

Run with code printing enabled for debugging:
```bash
weave --print-code -- ./myprogram
```

## Command-line Options

* `--print-code` - Print the translated code during execution (useful for debugging Weave itself)

## Environment Variables

Weave respects the `RUST_LOG` environment variable for controlling log output:

```bash
RUST_LOG=debug weave ./myprogram    # Enable debug logging
RUST_LOG=trace weave ./myprogram    # Enable trace logging
```

## Limitations

### Platform Support

Weave currently has limited platform support:
* **Darwin/arm64** - Early support
* **Linux/x86** - Early support

### Executable Types

* **Statically linked executables** are currently not supported, which means that Go applications, for example, don't run under Weave.

### System Call and libc Coverage

Weave provides limited coverage of system calls and C standard library functions. See [COMPAT.md](COMPAT.md) for detailed compatibility information, including:
* Supported ARM64 instructions and registers
* XNU syscall support status
* libc function support status

Currently supported libc functions include:
* `printf` (via host)
* `rand` / `srand` (emulated for determinism)
* `time` (emulated for determinism)

## Troubleshooting

### Program Crashes or Hangs

If your program crashes or hangs under Weave:

1. **Check compatibility** - Verify your program doesn't use unsupported system calls or libc functions by consulting [COMPAT.md](COMPAT.md)
2. **Enable logging** - Run with `RUST_LOG=debug` or `RUST_LOG=trace` to see what Weave is doing
3. **Use --print-code** - Enable code printing to see the binary translation output

### Unsupported Features

If you encounter a feature that isn't supported, check [COMPAT.md](COMPAT.md) for the current status of:
* System calls
* libc functions
* Architecture-specific instructions
