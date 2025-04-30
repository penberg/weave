# Weave Contributor Guide

## Debugging Weave

You can run `weave` under a debugger as follows:

```
cargo build && lldb -- ./target/debug/weave <program>
```

To weed out non-deterministic behavior in the tool, it's a good practice to
run a program with `weave` multiple times:

```
./scripts/repeat ./target/debug/weave <program>
```

## Further Reading

Weave is a binary translator and an userspace operating system. This section provides a collection of resources -- books, reference manuals, articles, and blog posts -- that are helpful for understanding the technological foundations.

### Dynamic Binary Modification

Dynamic binary modification is the technique Weave uses to transform non-deterministic programs into deterministic ones, by intercepting non-deterministic hardware instruction (such as system calls and random number generation) to calls into deterministic emulation.

To learn more about dynamic binary modification, the following resources are helpful:

* The book [Dynamic Binary Modification: Tools, Techniques and Applications] by Kim Hazelwood (2011) gives an overview of dynamic binary modification techniques.
* The paper [Optimising Dynamic Binary Modification Across 64-bit Arm Microarchitectures] by Guillermo Callaghan et al. (2020) describe an optimized dynamic binary modification system for ARM64.
* The paper [Transparent Dynamic Instrumentation] by Derek Bruening et al. (2012) describe an optimized dynamic binary modification system for x86.

### Dynamic linking and loading

The operating system kernel loads programs for execution using the `execve()` system call, which Weave emulates to enable binary translation of the programs.
The `execve()` system call needs to know the executable image file format and also provide means for dynamically loading libraries when required.
Linux uses a file format called ELF, and Darwin uses Mach-O. The OS implements dynamic linking by first loading a linker program, such as `ld-linux.so` or `dyld`, with `execve()`.
The dynamic linker then—in userspace—parses the executable image and loads shared libraries as needed.
Weave supports dynamic linking and loading directly in the `execve()` system call emulation for simplicity.

To understand the linking and loading process, the following resources are helpful:

* The book [Linkers & Loaders] by John R. Levine (1999) is an excellent resource for understanding how object files are transformed into runnable programs.
* [Ian Lance Taylor's essays on linkers] is also great reference on linkers

#### Linux (ELF Format)

Linux uses the ELF object file format, with dynamic linking and loading is done by the `ld-linux.so` program.

* The [Executable and Linking Format (ELF) Specification] serves as the reference specification for the object file format.
* The [System V Application Binary Interface AMD64 Architecture Processor Supplement] documents the x86-64 application binary interface (ABI), including ELF

#### Darwin (Mach-O Format)

Darwin uses the Mach-O file format, with dynamic linking and loading is done by the `dyld` program.

* While not as well-documented as ELF, information can be found in the [OS X ABI Mach-O File Format Reference]
* [Mach-O Binaries] and [Inside a Hello World executable on OS X] are good tutorials on the Mach-O format.

[Dynamic Binary Modification: Tools, Techniques and Applications]: https://link.springer.com/book/10.1007/978-3-031-01732-2
[Executable and Linking Format (ELF) Specification]: https://refspecs.linuxbase.org/elf/elf.pdf
[Ian Lance Taylor's essays on linkers]: https://lwn.net/Articles/276782/
[Inside a Hello World executable on OS X]: https://adrummond.net/posts/macho
[Linkers & Loaders]: http://www.staroceans.org/e-book/LinkersAndLoaders.pdf
[Mach-O Binaries]: https://www.m4b.io/reverse/engineering/mach/binaries/2015/03/29/mach-binaries.html
[Optimising Dynamic Binary Modification Across 64-bit Arm Microarchitectures]: https://research.manchester.ac.uk/en/publicationsoptimising-dynamic-binary-modification-across-64-bit-arm-microarc
[OS X ABI Mach-O File Format Reference]: https://github.com/aidansteele/osx-abi-macho-file-format-reference
[System V Application Binary Interface AMD64 Architecture Processor Supplement]: https://cs61.seas.harvard.edu/site/2022/pdf/x86-64-abi-20210928.pdf
[Transparent Dynamic Instrumentation]: https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/38225.pdf