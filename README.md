# old-linux-kernel-compat-layer

A minimal ptrace/seccomp-based compatibility layer (Rust crate, `x86_64` Linux) for running binaries built against a modern glibc (such as an Arch Linux `--enable-kernel=4.4` glibc) on ancient Linux kernels, down to **Linux 2.6.8**.

This layer was originally written inside [Anylinux-sharun](https://github.com/pkgforge-dev/Anylinux-sharun) and was split off into its own crate so that other projects can reuse it directly without duplicating the tracer or shelling out to `sharun`.

## What it handles

Modern binaries and libc builds both execute instructions old kernels do not enable and call syscalls that did not exist yet. The layer catches `SIGILL` to emulate unsupported instructions (`XGETBV` with `XCR0 = 0`) and intercepts missing syscalls at trace time. Most syscalls are rewritten in place to an older equivalent; syscalls that no single older call can answer are emulated with a short sequence of injected syscalls inside the traced process. Each translation is gated on a one-time probe (or a kernel version check when there is nothing reliable to probe):

- **`FUTEX_WAIT_BITSET` / `FUTEX_WAKE_BITSET`** (2.6.25) -> `FUTEX_WAIT` / `FUTEX_WAKE`, and **`FUTEX_CLOCK_REALTIME`** waits (2.6.29) -> plain waits with a relative timeout.
- **`O_CLOEXEC`** (2.6.23) cleared from `open` and `openat` flags on pre-2.6.23 kernels (avoids vendor kernels such as Fedora Core 3/4 returning errno 530 instead of `ENOENT`).
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

## Behavior & limits

- **`x86_64` Linux only.** On other architectures the crate still compiles cleanly as a no-op shim (`enabled()` returns `false`, `enter()` is a no-op, `run_traced` / `run_command_traced` run the target directly).
- **No 32-bit translation.** 32-bit tracees are traced and have their signals forwarded, but their syscalls are never rewritten.
- **Seccomp vs. ptrace fallback.** On kernels with seccomp-bpf (3.5+), only the needed syscalls trap into the tracer (this sets `no_new_privs`, so setuid helpers cannot gain privileges). Older kernels fall back to tracing every syscall with ptrace.
- **Nested / multi-process conflict prevention.** When the layer activates, it exports `OLD_KERNEL_COMPAT_ACTIVE=<tracer_pid>` to the traced child process. Any descendant binary that also embeds this crate checks both `/proc/self/status` (`TracerPid != 0`) and `OLD_KERNEL_COMPAT_ACTIVE` via `is_active()` (which `enabled()` and `enter()`/`run_traced()` check automatically):
  - If already traced, `enabled()` returns `false` and `enter()` / `run_traced()` run directly without forking a second tracer, installing a second seccomp filter, or printing a spurious `ptrace unavailable` warning — even if the child clears its environment (`env -i`) or uses different `Config` env var names.
  - If `/proc/self/status` is readable and reports `TracerPid: 0`, any leftover `OLD_KERNEL_COMPAT_ACTIVE` is treated as stale and ignored so a detached or post-tracer process is not left unprotected.
  - If `/proc` is unavailable in a descendant, `OLD_KERNEL_COMPAT_ACTIVE` still acts as a fallback guard.

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
        kernel_compat::run_traced(&|| {
            // exec your target here
        });
    }
}
```

Or run an arbitrary command under the layer with `kernel_compat::run_command_traced(&args)`.

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
- `OLD_KERNEL_COMPAT_ACTIVE` (set automatically by the layer): holds the active tracer PID for child processes (see `ENV_ACTIVE` / `is_active()`).

## License

MIT — see [LICENSE](LICENSE).
