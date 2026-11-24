//! Minimal ptrace/seccomp-based compatibility layer for running modern Linux
//! binaries (such as binaries built against a modern `--enable-kernel=4.4`
//! glibc) on ancient x86_64 Linux kernels, down to Linux 2.6.8.
//!
//! Originally developed inside
//! [Anylinux-sharun](https://github.com/pkgforge-dev/Anylinux-sharun) and split
//! into a standalone crate so other projects can embed the same layer directly.
//!
//! On non-`x86_64` architectures this crate compiles cleanly as a no-op shim:
//! [`enabled`] returns `false`, [`enter`] is a no-op, and [`run_traced`] /
//! [`run_command_traced`] execute the target directly without tracing.

#[cfg(target_arch = "x86_64")]
mod emulated_syscalls;
#[cfg(target_arch = "x86_64")]
mod kernel_compat;

use std::process::exit;

/// Internal-only flag used by the `PR_SET_NO_NEW_PRIVS` + `execve` probe.
///
/// The probe re-executes `/proc/self/exe` with this argument to check whether
/// setting `no_new_privs` breaks `execve` on the host kernel (observed on some
/// 3.8 kernels). Call [`exit_if_internal_probe`] early in `main()` so the
/// probe exits immediately with status 0 instead of running your application.
pub const NNP_PROBE_FLAG: &str = "--old-kernel-compat-internal-probe-execve-after-no-new-privs";

/// Configuration for the compatibility layer's environment variable names,
/// log prefix, and internal probe sentinel.
#[derive(Clone, Copy, Debug)]
pub struct Config {
	/// Primary environment variable controlling enablement (`1` forces on, `0`
	/// disables, unset auto-detects).
	pub env_enable: &'static str,
	/// Optional fallback enablement env var (checked if `env_enable` is unset).
	pub env_enable_fallback: Option<&'static str>,
	/// Environment variable enabling translation debug logs (`=1`).
	pub env_debug: &'static str,
	/// Optional fallback debug env var.
	pub env_debug_fallback: Option<&'static str>,
	/// Environment variable enabling noisy per-syscall logs (`=1`).
	pub env_debug_all: &'static str,
	/// Optional fallback per-syscall debug env var.
	pub env_debug_all_fallback: Option<&'static str>,
	/// Prefix used in user-facing status lines, e.g. `"[sharun]"` or
	/// `"[kernel-compat]"`.
	pub log_prefix: &'static str,
	/// Sentinel CLI argument passed to `/proc/self/exe` by the `no_new_privs`
	/// `execve` probe.
	pub nnp_probe_flag: &'static str,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			env_enable: "OLD_KERNEL_COMPAT",
			env_enable_fallback: Some("SHARUN_OLD_KERNEL_COMPAT"),
			env_debug: "OLD_KERNEL_COMPAT_DEBUG",
			env_debug_fallback: Some("SHARUN_OLD_KERNEL_COMPAT_DEBUG"),
			env_debug_all: "OLD_KERNEL_COMPAT_DEBUG_ALL",
			env_debug_all_fallback: Some("SHARUN_OLD_KERNEL_COMPAT_DEBUG_ALL"),
			log_prefix: "[kernel-compat]",
			nnp_probe_flag: NNP_PROBE_FLAG,
		}
	}
}

/// Configure env var names, log prefix, and probe sentinel before calling
/// [`enabled`], [`enter`], [`run_traced`], or [`run_command_traced`].
///
/// Only the first call takes effect; subsequent calls return `Err(config)`.
pub fn init(config: Config) -> Result<(), Config> {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::init(config)
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		let _ = config;
		Ok(())
	}
}

/// If the current process was launched as the internal `no_new_privs` probe,
/// exit immediately with status 0. Call this near the start of `main()`.
pub fn exit_if_internal_probe() {
	let flag = current_probe_flag();
	if std::env::args().skip(1).any(|arg| arg == flag) {
		exit(0);
	}
}

/// Return `true` if `args` (typically `env::args().skip(1)`) contains the
/// internal `no_new_privs` probe flag.
pub fn is_internal_probe<I, S>(args: I) -> bool
where
	I: IntoIterator<Item = S>,
	S: AsRef<str>,
{
	let flag = current_probe_flag();
	args.into_iter().any(|arg| arg.as_ref() == flag)
}

fn current_probe_flag() -> &'static str {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::config().nnp_probe_flag
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		NNP_PROBE_FLAG
	}
}

/// Whether the compatibility layer should be activated for this launch.
///
/// Always returns `false` on non-`x86_64` targets.
pub fn enabled() -> bool {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::enabled()
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		false
	}
}

/// Whether the running kernel is older than `(major, minor, patch)`.
pub fn kernel_lt(major: u64, minor: u64, patch: u64) -> bool {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::kernel_lt(major, minor, patch)
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		let _ = (major, minor, patch);
		false
	}
}

/// Activate the compatibility layer for the current process if [`enabled`] is
/// true.
///
/// Must be called early in `main()`, before spawning any threads (and after
/// [`exit_if_internal_probe`]). When active, this forks a tracer supervisor in
/// the parent process (which waits for the child and exits with its status) and
/// returns in the traced child so the rest of `main()` executes under the
/// compatibility layer.
///
/// Returns immediately without forking when the layer is disabled, already
/// active (`TracerPid != 0`), `ptrace` is unavailable, or on non-`x86_64`
/// targets.
pub fn enter() {
	#[cfg(target_arch = "x86_64")]
	{
		if kernel_compat::enabled() {
			kernel_compat::enter_traced();
		}
	}
}

/// Fork a supervisor process and run `launch` inside the traced child, never
/// returning.
///
/// If this process is already traced (`TracerPid != 0`), if `ptrace` is
/// unavailable, or on non-`x86_64` architectures, `launch` is invoked directly.
pub fn run_traced(launch: &dyn Fn()) -> ! {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::run_traced(launch)
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		launch();
		exit(1)
	}
}

/// Run an arbitrary command (`args[0]` looked up in `PATH`, with `args[1..]`)
/// under the compatibility tracer if [`enabled`] is true, or `exec` it directly
/// otherwise. Never returns.
pub fn run_command_traced(args: &[String]) -> ! {
	#[cfg(target_arch = "x86_64")]
	{
		kernel_compat::run_command_traced(args)
	}
	#[cfg(not(target_arch = "x86_64"))]
	{
		if args.is_empty() {
			eprintln!("[kernel-compat] no command specified");
			exit(1);
		}
		let err = std::os::unix::process::CommandExt::exec(
			std::process::Command::new(&args[0]).args(&args[1..]),
		);
		eprintln!("[kernel-compat] failed to execute {}: {err}", args[0]);
		exit(127)
	}
}
