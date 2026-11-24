# old-linux-kernel-compat-layer

A minimal ptrace/seccomp-based compatibility layer (Rust crate, `x86_64` and `aarch64` Linux) for running binaries built against a modern glibc (such as an Arch Linux `--enable-kernel=4.4` glibc) on ancient Linux kernels:

- **`x86_64`**: down to **Linux 2.6.8** (Debian 3.1)
- **`aarch64`**: down to **Linux 3.11** (Ubuntu 13.10 Saucy Salamander, the first Ubuntu release with `arm64`)

This layer was originally written inside [Anylinux-sharun](https://github.com/pkgforge-dev/Anylinux-sharun) and was split off into its own crate so that other projects can reuse it directly without duplicating the tracer or shelling out to `sharun`.

## What it handles

Modern binaries and libc builds both execute instructions old kernels do not enable and call syscalls that did not exist yet. The layer catches `SIGILL` to emulate unsupported instructions and intercepts missing syscalls at trace time. Each translation is gated on a one-time probe (or a kernel version check when there is nothing reliable to probe).

### `x86_64` (down to Linux 2.6.8)

Most syscalls are rewritten in place to an older equivalent; syscalls that no single older call can answer are emulated with a short sequence of injected syscalls inside the traced process. `SIGILL` emulates `XGETBV` with `XCR0 = 0`.

- **`FUTEX_WAIT_BITSET` / `FUTEX_WAKE_BITSET`** (2.6.25) -> `FUTEX_WAIT` / `FUTEX_WAKE`, and **`FUTEX_CLOCK_REALTIME`** waits (2.6.29) -> plain waits with a relative timeout.
- **`O_CLOEXEC`** (2.6.23) cleared from `open` and `openat` flags on pre-2.6.23 kernels (avoids vendor kernels such as Fedora Core 3/4 returning errno 530 instead of `ENOENT`).
- **`clone(CLONE_THREAD)`** (2.6.2) gets `CLONE_DETACHED` added on 2.6.0 and 2.6.1, which refuse a thread without it (glibc's `pthread_create` never sets it).
- **`pipe2`** (2.6.27) -> emulated as `pipe` + `fcntl` so `O_NONBLOCK` and `O_CLOEXEC` are preserved (`O_DIRECT` falls back to plain `pipe`).
- **The `*at` syscall family** (2.6.16: `openat`, `newfstatat`, `mkdirat`, `mknodat`, `fchownat`, `futimesat`, `unlinkat`, `renameat`, `linkat`, `symlinkat`, `readlinkat`, `fchmodat`, `faccessat`) -> plain syscalls, rebuilding dirfd-relative paths through `/proc/self/fd/<fd>/<path>` (needs `/proc`).
- **`statx`** (4.11) -> `newfstatat` / `fstat` (or `stat` / `lstat` / `fstat` where `newfstatat` is also missing), translating `struct stat` into `struct statx`.
- **`getrandom`** (3.17) -> filled from `/dev/urandom`.
- **`ppoll`** (2.6.19) -> `poll`.
- **`epoll_pwait`** (2.6.19) -> emulated as `rt_sigprocmask` + `epoll_wait` + `rt_sigprocmask`.
- **`epoll_create1`** (2.6.27) -> `epoll_create`.
- **`prlimit64`** (2.6.36) -> `getrlimit` / `setrlimit` for the calling process.
- **`pwritev` / `preadv`** (2.6.30) -> emulated as `lseek` + `writev` / `readv`.
- **`fcntl(F_DUPFD_CLOEXEC)`** (2.6.24) -> emulated as `F_DUPFD` + `FD_CLOEXEC`.
- **`eventfd` / `eventfd2`** (2.6.22 / 2.6.27) -> emulated with a self-connected abstract `AF_UNIX` datagram socket.
- **`timerfd_create` / `timerfd_settime` / `timerfd_gettime`** (2.6.25) -> emulated with a pipe driven by the tracer via `ITIMER_REAL` (needs `/proc`).
- **`termios2` ioctls** (`TCGETS2`, `TCSETS2`, `TCSETSW2`, `TCSETSF2`, 2.6.20) -> legacy `TCGETS` / `TCSETS*`, decoding baud rate from `c_cflag`.
- **Newer clock IDs** (`CLOCK_MONOTONIC_RAW` 2.6.28, `CLOCK_REALTIME_COARSE` / `CLOCK_MONOTONIC_COARSE` 2.6.32, `CLOCK_BOOTTIME` 2.6.39) -> closest supported clock.
- **Echoed syscall numbers** on pre-2.6.19 traced `x86_64` kernels -> normalized back to `-ENOSYS` for unimplemented syscalls above the kernel's syscall table.
- **Linux 2.6.12 duplicate syscall-exit stops** -> skipped without desynchronizing entry/exit pairing.

### `aarch64` (down to Linux 3.11)

`arm64` entered mainline Linux in 3.7 with the `asm-generic` syscall ABI, so all pre-3.11 syscalls (`*at`, `futex` bitset/realtime, `pipe2`, `epoll_*`, `ppoll`, `prlimit64`, `eventfd2`, `timerfd_*`, `pwritev`/`preadv`, `F_DUPFD_CLOEXEC`, `termios2`, `O_CLOEXEC`, `CLOCK_BOOTTIME`/`*_COARSE`) are already present in Linux 3.11. The `aarch64` backend handles the post-3.11 gaps:

- **`getrandom`** (3.17) -> filled from `/dev/urandom` at syscall exit.
- **`statx`** (4.11) -> `newfstatat` / `fstat`, translating the `asm-generic` 64-bit `struct stat` (128 bytes) into `struct statx`:
  - On Linux >= 3.19, rewritten in place at entry/seccomp stop via `PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL)`.
  - On Linux 3.11–3.18 (before `NT_ARM_SYSTEM_CALL` existed), replayed via `svc #0` once `statx` returns `-ENOSYS`, then original registers are restored.
- **`SIGILL` on `MRS` of EL1 CPU ID registers** (`HWCAP_CPUID`, added in 4.11) -> emulated as returning `0` (no optional extensions) and advancing `pc` by 4.

## Behavior & limits

- **`x86_64` and `aarch64` Linux.** On other architectures the crate compiles cleanly as a no-op shim (`enabled()` returns `false`, `enter()` is a no-op, `run_traced` / `run_command_traced` run the target directly).
- **No 32-bit translation.** 32-bit tracees (`i386` on `x86_64`, `AArch32` on `aarch64`) are traced and have their signals forwarded, but their syscalls and instructions are never rewritten.
- **Seccomp vs. ptrace fallback.** On kernels with seccomp-bpf (`x86_64` 3.5+, `aarch64` 3.19+), only the needed syscalls trap into the tracer (this sets `no_new_privs`, so setuid helpers cannot gain privileges). Older kernels fall back to tracing every syscall with ptrace.
- **Nested / multi-process conflict prevention.** When the layer activates, it sets `OLD_KERNEL_COMPAT_ACTIVE=1` (`ENV_ACTIVE`) in the traced child process. Any descendant binary built with this crate checks that environment variable in `is_active()` (and automatically in `enabled()`, `enter()`, `run_traced()`, and `run_command_traced()`), so it skips starting a second tracer or emulating syscalls again — even on minimal systems without `/proc` or when outer and inner binaries use different `Config` env var names.

## Usage

Add this repository as a Git dependency in `Cargo.toml`:

```toml
[dependencies]
old-linux-kernel-compat-layer = { git = "https://github.com/pkgforge-dev/old-linux-kernel-compat-layer" }
```

### Protecting the current process (`enter`)

Call `exit_if_internal_probe()` and `enter()` early in `main()`, before spawning any threads:

```rust
use old_linux_kernel_compat_layer as kernel_compat;

fn main() {
    // Handle the internal no_new_privs/execve self-probe.
    kernel_compat::exit_if_internal_probe();

    // If needed on this kernel, forks a supervisor in the parent and
    // returns in the traced child so the rest of main() runs under the layer.
    kernel_compat::enter();

    // ... normal program logic ...
}
```

### Wrapping a launch function or external command

```rust
use old_linux_kernel_compat_layer as kernel_compat;

fn main() {
    kernel_compat::exit_if_internal_probe();

    if kernel_compat::enabled() {
        kernel_compat::run_traced(|| {
            // exec your target here (closures may move owned args)
        });
    }
}
```

Or run an arbitrary command under the layer with `kernel_compat::run_command_traced(&args)`.

To wrap only a specific helper binary on kernels that lack the `*at` syscalls (`< 2.6.16` on `x86_64`), gate on `kernel_compat::at_syscalls_missing()` (returns `false` on `>= 2.6.16`, `aarch64`, and unsupported architectures):

```rust
if kernel_compat::at_syscalls_missing() {
    kernel_compat::run_traced(|| exec_helper(owned_args));
}
```

### Customizing environment variables and log prefix

Call `init(Config { .. })` before `exit_if_internal_probe()` / `enabled()` / `enter()` if you want project-specific environment variable names or log prefixes:

```rust
use old_linux_kernel_compat_layer::{self as kernel_compat, Config};

fn main() {
    let _ = kernel_compat::init(Config {
        env_enable: "MYAPP_OLD_KERNEL_COMPAT",
        env_enable_fallback: Some("OLD_KERNEL_COMPAT"),
        env_debug: "MYAPP_OLD_KERNEL_COMPAT_DEBUG",
        env_debug_fallback: Some("OLD_KERNEL_COMPAT_DEBUG"),
        env_debug_all: "MYAPP_OLD_KERNEL_COMPAT_DEBUG_ALL",
        env_debug_all_fallback: Some("OLD_KERNEL_COMPAT_DEBUG_ALL"),
        log_prefix: "[myapp]",
        ..Config::default()
    });
    kernel_compat::exit_if_internal_probe();
    kernel_compat::enter();
}
```

## Environment variables (defaults)

- `OLD_KERNEL_COMPAT` (fallback: `SHARUN_OLD_KERNEL_COMPAT`): `1` forces the layer on, `0` disables it, unset auto-enables on kernels older than 4.0 or when `statx` is missing.
- `OLD_KERNEL_COMPAT_DEBUG` (fallback: `SHARUN_OLD_KERNEL_COMPAT_DEBUG`): `1` logs translations to stderr.
- `OLD_KERNEL_COMPAT_DEBUG_ALL` (fallback: `SHARUN_OLD_KERNEL_COMPAT_DEBUG_ALL`): `1` also logs every syscall and its return value (very noisy and slow).
- `OLD_KERNEL_COMPAT_ACTIVE` (set to `1` automatically by the layer): signals to child processes built with this crate that the compatibility layer is already active (see `ENV_ACTIVE` / `is_active()`).

## License

MIT — see [LICENSE](LICENSE).
