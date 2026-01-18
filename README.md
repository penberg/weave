<p align="center">
  <img src=".github/assets/weave-logo.jpg" alt="Weave" width="300"/>
  <h1 align="center">Weave</h1>
</p>

<p align="center">
Deterministic execution for reproducible debugging—for AI agents and humans.
</p>

---

## 🎯 Overview

Modern software contains non-deterministic bugs that appear randomly and disappear when attempting to reproduce them. Weave eliminates this unpredictability by controlling all sources of randomness, providing a systematic approach to debugging hard-to-reproduce bugs for both AI coding agents and humans with perfect repeatability.

> [!NOTE]
> **Weave is currently in early development and only has [limited support](COMPAT.md) for Darwin/arm64 and Linux/x86.**

### Features

* Deterministic time simulation
* Runs on Darwin/arm64 and Linux/x86

## 🧑‍💻 Getting Started

You use the `weave` program to run your programs as follows:

```console
weave <program>
```

## 💡 Motivation

Modern systems introduce non-determinism at every layer. Even with identical inputs, implicit sources of randomness — such as system time, random number generation, and thread scheduling — cause programs to behave differently each time. This unpredictability creates debugging nightmares: complex bugs that emerge from subtle component interactions, only to _disappear_ when you attempt to reproduce them.

When you encounter a non-deterministic bug during development or testing, you cannot reliably reproduce the issue, let alone understand and fix it. Developers waste time chasing phantom bugs or implementing fixes that don't address the root cause, as the bug's appearance depends on unpredictable system states. This non-determinism fundamentally limits debugging effectiveness, turning what should be systematic problem-solving into frustrating guesswork.

## 🔧 How Weave Works

<img align="right" width="40%" src=".github/assets/weave-architecture.svg">

Weave solves the problem by eliminating non-determinism from program execution. By intercepting and controlling every source of randomness, Weave transforms unpredictable program execution into perfectly repeatable runs. Every execution becomes identical, making those elusive bugs reproducible and fixable.

This repeatability is essential for AI coding agents that need consistent, reproducible behavior to debug and improve code effectively. Of course, having perfect reproducibility is useful for us humans too. With Weave, AI coding agents and humans can confidently identify, analyze, and fix even the most complex bugs that plague modern distributed systems—the kinds of bugs that are out of reach for AI coding agents and would take weeks to track down in traditional environments for humans.

Weave uses a low-overhead dynamic binary modification approach inspired by [MAMBO] (Callaghan et al., 2020) and [DynamoRIO] (Bruening et al., 2012). The core of Weave is a _supervisor_, which consists of a userspace kernel and a deterministic C standard library (libc) that uses a binary translator to execute guest programs.

Weave starts by calling the supervisor `execve()` function, which emulates the same system call and dynamic linker to load the _guest program_ in the same memory space as Weave. When the guest program is loaded into memory, the supervisor uses the _binary translator_ to replace non-deterministic execution with deterministic execution. For example, when the supervisor sees a system call invocation instruction, it translates that to a function call into the userspace kernel.

The binary translation works at the basic block level, translating one basic block at a time. At program startup, Weave translates the first basic block and begins executing it. At the end of the basic block, there is an exit stub that calls into a _dispatcher_, which is responsible for translating the next basic block.

By combining deterministic execution with binary translation, Weave makes previously unreproducible bugs reproducible. This allows both AI coding agents and humans to debug complex systems more effectively, turning what used to be multi-week investigations into repeatable, solvable problems.

## 🤔 FAQ

### How is Weave different from _X_?

**[Antithesis]** is an autonomous testing platform. The platform runs on a <i>[deterministic hypervisor]</i>, which serves a similar purpose as Weave in turning non-deterministic execution into repeatable runs. However, Weave's approach is more lightweight, focusing on repeatable runs on a local development machine, whereas Antithesis is a feature rich-service for autonomous testing, including fault injection for networking and more.

**[Hermit]** is a program that translates non-deterministic program behavior into deterministic, repeatable behavior, similar to what Weave aims to do, but using `ptrace` to intercept system calls (Leija, 2020). Unfortunately, Hermit is no longer under active development and is limited to Linux/x86-64.

## License

This project is licensed under the [MIT license].

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Turso Database by you, shall be licensed as MIT, without any additional
terms or conditions.

[MIT license]: LICENSE.md

## 🎓 Theory

Derek Bruening, Qin Zhao, and Saman Amarasinghe. (2012). "[Transparent Dynamic Instrumentation](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/38225.pdf). In _VEE '12_.

Guillermo Callaghan, Cosmin Gorgovan and Mikel Luján. (2020). "[Optimising Dynamic Binary Modification Across 64-bit Arm Microarchitectures](https://research.manchester.ac.uk/en/publications/optimising-dynamic-binary-modification-across-64-bit-arm-microarc)." In _VEE '20_.

Kim Hazelwood. (2011). "[Dynamic Binary Modification: Tools, Techniques and Applications](https://link.springer.com/book/10.1007/978-3-031-01732-2)".

Omar S. Navarro Leija, Kelly Shiptoski, Ryan G. Scott, Baojun Wang, Nicholas Renner, Ryan R. Newton, and Joseph Devietti. (2020). "[Reproducible Containers](https://krs85.github.io/dettrace.pdf)". In _ASPLOS '20_.

Junfeng Yang, Tisheng Chen, Ming Wu, Zhilei Xu, Xuezheng Liu, Haoxiang Lin, Mao Yang, Fan Long, Lintao Zhang and Lidong Zhou. (2009). "[MODIST: Transparent Model Checking of Unmodified Distributed Systems](https://www.usenix.org/legacy/events/nsdi09/tech/full_papers/yang/yang.pdf)". In _NSDI '09_.


[Antithesis]: https://antithesis.com

[DynamoRIO]: https://dynamorio.org

[deterministic hypervisor]: https://antithesis.com/blog/deterministic_hypervisor/

[Hermit]: https://github.com/facebookexperimental/hermit

[MAMBO]: https://github.com/beehive-lab/mambo
