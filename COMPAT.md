# Weave compatibility

## ARM64

ARM64 instructions and external registers that have non-deterministic behavior.

### Instructions

| Instruction | Supported |
|-------------|-----------|
| RNDR | No |
| RNDRRS | No |
| SVC | Yes |

### External Registers

| Register name | Supported |
|---------------|-----------|
| CNTVCT | No |

## XNU syscalls

| System Call Name | Number | Supported |
|------------------|--------|-----------|
| exit | 1 | No |
| fork | 2 | No |
| read | 3 | No |
| write | 4 | No |
| open | 5 | No |
| close | 6 | No |
| wait4 | 7 | No |
| link | 9 | No |
| unlink | 10 | No |
| chdir | 12 | No |
| fchdir | 13 | No |
| mknod | 14 | No |
| chmod | 15 | No |
| chown | 16 | No |
| getfsstat | 18 | No |
| getpid | 20 | No |
| setuid | 23 | No |
| getuid | 24 | No |
| geteuid | 25 | No |
| ptrace | 26 | No |
| recvmsg | 27 | No |
| sendmsg | 28 | No |
| recvfrom | 29 | No |
| accept | 30 | No |
| getpeername | 31 | No |
| getsockname | 32 | No |
| access | 33 | No |
| chflags | 34 | No |
| fchflags | 35 | No |
| sync | 36 | No |
| kill | 37 | No |
| getppid | 39 | No |
| dup | 41 | No |
| pipe | 42 | No |
| getegid | 43 | No |
| sigaction | 46 | No |
| getgid | 47 | No |
| sigprocmask | 48 | No |
| getlogin | 49 | No |
| setlogin | 50 | No |
| acct | 51 | No |
| sigpending | 52 | No |
| sigaltstack | 53 | No |
| ioctl | 54 | No |
| reboot | 55 | No |
| revoke | 56 | No |
| symlink | 57 | No |
| readlink | 58 | No |
| execve | 59 | No |
| umask | 60 | No |
| chroot | 61 | No |
| msync | 65 | No |
| vfork | 66 | No |
| munmap | 73 | No |
| mprotect | 74 | No |
| madvise | 75 | No |
| mincore | 78 | No |
| getgroups | 79 | No |
| setgroups | 80 | No |
| getpgrp | 81 | No |
| setpgid | 82 | No |
| setitimer | 83 | No |
| swapon | 85 | No |
| getitimer | 86 | No |
| getdtablesize | 89 | No |
| dup2 | 90 | No |
| fcntl | 92 | No |
| select | 93 | No |
| fsync | 95 | No |
| setpriority | 96 | No |
| socket | 97 | No |
| connect | 98 | No |
| getpriority | 100 | No |
| bind | 104 | No |
| setsockopt | 105 | No |
| listen | 106 | No |
| sigsuspend | 111 | No |
| gettimeofday | 116 | No |
| getrusage | 117 | No |
| getsockopt | 118 | No |
| readv | 120 | No |
| writev | 121 | No |
| settimeofday | 122 | No |
| fchown | 123 | No |
| fchmod | 124 | No |
| setreuid | 126 | No |
| setregid | 127 | No |
| rename | 128 | No |
| flock | 131 | No |
| mkfifo | 132 | No |
| sendto | 133 | No |
| shutdown | 134 | No |
| socketpair | 135 | No |
| mkdir | 136 | No |
| rmdir | 137 | No |
| utimes | 138 | No |
| futimes | 139 | No |
| adjtime | 140 | No |
| gethostuuid | 142 | No |
| setsid | 147 | No |
| getpgid | 151 | No |
| setprivexec | 152 | No |
| pread | 153 | No |
| pwrite | 154 | No |
| statfs | 157 | No |
| fstatfs | 158 | No |
| unmount | 159 | No |
| quotactl | 165 | No |
| mount | 167 | No |
| csops | 169 | No |
| 170 old table | 170 | No |
| waitid | 173 | No |
| kdebug_trace | 180 | No |
| setgid | 181 | No |
| setegid | 182 | No |
| seteuid | 183 | No |
| sigreturn | 184 | No |
| chud | 185 | No |
| fdatasync | 187 | No |
| stat | 188 | No |
| fstat | 189 | No |
| lstat | 190 | No |
| pathconf | 191 | No |
| fpathconf | 192 | No |
| getrlimit | 194 | No |
| setrlimit | 195 | No |
| getdirentries | 196 | No |
| mmap | 197 | No |
| lseek | 199 | No |
| truncate | 200 | No |
| ftruncate | 201 | No |
| __sysctl | 202 | No |
| mlock | 203 | No |
| munlock | 204 | No |
| undelete | 205 | No |
| mkcomplex | 216 | No |
| getattrlist | 220 | No |
| setattrlist | 221 | No |
| getdirentriesattr | 222 | No |
| exchangedata | 223 | No |
| searchfs | 225 | No |
| delete | 226 | No |
| copyfile | 227 | No |
| fgetattrlist | 228 | No |
| fsetattrlist | 229 | No |
| poll | 230 | No |
| watchevent | 231 | No |
| waitevent | 232 | No |
| modwatch | 233 | No |
| getxattr | 234 | No |
| fgetxattr | 235 | No |
| setxattr | 236 | No |
| fsetxattr | 237 | No |
| removexattr | 238 | No |
| fremovexattr | 239 | No |
| listxattr | 240 | No |
| flistxattr | 241 | No |
| fsctl | 242 | No |
| initgroups | 243 | No |
| posix_spawn | 244 | No |
| ffsctl | 245 | No |
| minherit | 250 | No |
| shm_open | 266 | No |
| shm_unlink | 267 | No |
| sem_open | 268 | No |
| sem_close | 269 | No |
| sem_unlink | 270 | No |
| sem_wait | 271 | No |
| sem_trywait | 272 | No |
| sem_post | 273 | No |
| sem_getvalue | 274 | No |
| sem_init | 275 | No |
| sem_destroy | 276 | No |
| open_extended | 277 | No |
| umask_extended | 278 | No |
| stat_extended | 279 | No |
| lstat_extended | 280 | No |
| fstat_extended | 281 | No |
| chmod_extended | 282 | No |
| fchmod_extended | 283 | No |
| access_extended | 284 | No |
| settid | 285 | No |
| gettid | 286 | No |
| setsgroups | 287 | No |
| getsgroups | 288 | No |
| setwgroups | 289 | No |
| getwgroups | 290 | No |
| mkfifo_extended | 291 | No |
| mkdir_extended | 292 | No |
| shared_region_check_np | 294 | No |
| vm_pressure_monitor | 296 | No |
| psynch_rw_longrdlock | 297 | No |
| psynch_rw_yieldwrlock | 298 | No |
| psynch_rw_downgrade | 299 | No |
| psynch_rw_upgrade | 300 | No |
| psynch_mutexwait | 301 | No |
| psynch_mutexdrop | 302 | No |
| psynch_cvbroad | 303 | No |
| psynch_cvsignal | 304 | No |
| psynch_cvwait | 305 | No |
| psynch_rw_rdlock | 306 | No |
| psynch_rw_wrlock | 307 | No |
| psynch_rw_unlock | 308 | No |
| psynch_rw_unlock2 | 309 | No |
| getsid | 310 | No |
| settid_with_pid | 311 | No |
| psynch_cvclrprepost | 312 | No |
| aio_fsync | 313 | No |
| aio_return | 314 | No |
| aio_suspend | 315 | No |
| aio_cancel | 316 | No |
| aio_error | 317 | No |
| aio_read | 318 | No |
| aio_write | 319 | No |
| lio_listio | 320 | No |
| iopolicysys | 322 | No |
| process_policy | 323 | No |
| mlockall | 324 | No |
| munlockall | 325 | No |
| issetugid | 327 | No |
| __pthread_kill | 328 | No |
| __pthread_sigmask | 329 | No |
| __sigwait | 330 | No |
| __disable_threadsignal | 331 | No |
| __pthread_markcancel | 332 | No |
| __pthread_canceled | 333 | No |
| __semwait_signal | 334 | No |
| proc_info | 336 | No |
| stat64 | 338 | No |
| fstat64 | 339 | No |
| lstat64 | 340 | No |
| stat64_extended | 341 | No |
| lstat64_extended | 342 | No |
| fstat64_extended | 343 | No |
| getdirentries64 | 344 | No |
| statfs64 | 345 | No |
| fstatfs64 | 346 | No |
| getfsstat64 | 347 | No |
| __pthread_chdir | 348 | No |
| __pthread_fchdir | 349 | No |
| audit | 350 | No |
| auditon | 351 | No |
| getauid | 353 | No |
| setauid | 354 | No |
| getaudit_addr | 357 | No |
| setaudit_addr | 358 | No |
| auditctl | 359 | No |
| bsdthread_create | 360 | No |
| bsdthread_terminate | 361 | No |
| kqueue | 362 | No |
| kevent | 363 | No |
| lchown | 364 | No |
| stack_snapshot | 365 | No |
| bsdthread_register | 366 | No |
| workq_open | 367 | No |
| workq_kernreturn | 368 | No |
| kevent64 | 369 | No |
| __old_semwait_signal | 370 | No |
| __old_semwait_signal_nocancel | 371 | No |
| thread_selfid | 372 | No |
| ledger | 373 | No |
| __mac_execve | 380 | No |
| __mac_syscall | 381 | No |
| __mac_get_file | 382 | No |
| __mac_set_file | 383 | No |
| __mac_get_link | 384 | No |
| __mac_set_link | 385 | No |
| __mac_get_proc | 386 | No |
| __mac_set_proc | 387 | No |
| __mac_get_fd | 388 | No |
| __mac_set_fd | 389 | No |
| __mac_get_pid | 390 | No |
| __mac_get_lcid | 391 | No |
| __mac_get_lctx | 392 | No |
| __mac_set_lctx | 393 | No |
| setlcid | 394 | No |
| getlcid | 395 | No |
| read_nocancel | 396 | No |
| write_nocancel | 397 | No |
| open_nocancel | 398 | No |
| close_nocancel | 399 | No |
| wait4_nocancel | 400 | No |
| recvmsg_nocancel | 401 | No |
| sendmsg_nocancel | 402 | No |
| recvfrom_nocancel | 403 | No |
| accept_nocancel | 404 | No |
| msync_nocancel | 405 | No |
| fcntl_nocancel | 406 | No |
| select_nocancel | 407 | No |
| fsync_nocancel | 408 | No |
| connect_nocancel | 409 | No |
| sigsuspend_nocancel | 410 | No |
| readv_nocancel | 411 | No |
| writev_nocancel | 412 | No |
| sendto_nocancel | 413 | No |
| pread_nocancel | 414 | No |
| pwrite_nocancel | 415 | No |
| waitid_nocancel | 416 | No |
| poll_nocancel | 417 | No |
| sem_wait_nocancel | 420 | No |
| aio_suspend_nocancel | 421 | No |
| __sigwait_nocancel | 422 | No |
| __semwait_signal_nocancel | 423 | No |
| __mac_mount | 424 | No |
| __mac_get_mount | 425 | No |
| __mac_getfsstat | 426 | No |
| fsgetpath | 427 | No |
| audit_session_self | 428 | No |
| audit_session_join | 429 | No |
| fileport_makeport | 430 | No |
| fileport_makefd | 431 | No |
| audit_session_port | 432 | No |
| pid_suspend | 433 | No |
| pid_resume | 434 | No |
| pid_hibernate | 435 | No |
| pid_shutdown_sockets | 436 | No |
| shared_region_map_and_slide_np | 438 | No |
| kas_info | 439 | No |
| memorystatus_control | 440 | No |
| guarded_open_np | 441 | No |
| guarded_close_np | 442 | No |

## libc

### `<ctype.h>`
Not supported.

### `<errno.h>`
Not supported.

### `<fenv.h>`
Not supported.

### `<float.h>`
Not supported.

### `<inttypes.h>`
Not supported.

### `<iso646.h>`
Not supported.

### `<limits.h>`
Not supported.

### `<locale.h>`
Not supported.

### `<math.h>`
Not supported.

### `<setjmp.h>`
Not supported.

### `<signal.h>`
Not supported.

### `<stdalign.h>`
Not supported.

### `<stdarg.h>`
Not supported.

### `<stdatomic.h>`
Not supported.

### `<stdbit.h>`
Not supported.

### `<stdbool.h>`
Not supported.

### `<stddef.h>`
Not supported.

### `<stdint.h>`
Not supported.

### `<stdio.h>`

| Function | Status |
|----------|--------|
| printf | Host |

### `<stdlib.h>`

| Function | Status |
|----------|--------|
| rand | Emulated |
| srand | Emulated |

### `<stdnoreturn.h>`
Not supported.

### `<string.h>`
Not supported.

### `<tgmath.h>`
Not supported.

### `<threads.h>`
Not supported.

### `<time.h>`

| Function | Status |
|----------|--------|
| time | Emulated |

### `<uchar.h>`
Not supported.

### `<wchar.h>`
Not supported.

### `<wctype.h>`
Not supported.