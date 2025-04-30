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
