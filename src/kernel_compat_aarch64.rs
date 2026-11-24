//! Minimal ptrace/seccomp-based kernel compatibility shim for `aarch64`.
//!
//! Minimum supported kernel: **Linux 3.11** (Ubuntu 13.10 Saucy Salamander, the
//! first Ubuntu release with `arm64`).
//!
//! Every syscall the x86_64 layer translates for pre-3.11 kernels (`*at`,
//! `futex` bitset/realtime, `pipe2`, `epoll_create1`, `epoll_pwait`, `ppoll`,
//! `prlimit64`, `eventfd2`, `timerfd_*`, `pwritev`/`preadv`, `F_DUPFD_CLOEXEC`,
//! `termios2`, `O_CLOEXEC`, `CLOCK_BOOTTIME` / `*_COARSE`) has been present on
//! `arm64` since its initial mainline release (Linux 3.7).
//!
//! Between Linux 3.11 and modern kernels (`--enable-kernel=4.4` / Qt6 / Rust),
//! the gaps that actually break modern `aarch64` binaries are:
//!
//! 1. **`getrandom`** (added in 3.17): emulated at syscall exit by filling the
//!    tracee's buffer from `/dev/urandom`.
//! 2. **`statx`** (added in 4.11): translated to `newfstatat` / `fstat` and
//!    converted from `asm-generic` 64-bit `struct stat` (128 bytes) into
//!    `struct statx`.
//!    - On Linux >= 3.19, `PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL)` rewrites the
//!      syscall number in place at syscall entry (or seccomp stop).
//!    - On Linux 3.11–3.18, `NT_ARM_SYSTEM_CALL` does not exist yet: the kernel
//!      dispatches using the saved `pt_regs.syscallno` rather than `regs[8]`, so
//!      a tracer cannot rewrite a syscall number at entry. Instead, when `statx`
//!      returns `-ENOSYS`, we back up `pc` by 4 (to the `svc #0` instruction)
//!      and execute `newfstatat`/`fstat` as a follow-up syscall, then translate
//!      the resulting `struct stat` and restore the original registers.
//! 3. **`SIGILL` on `MRS` of EL1 ID registers** (added in 4.11 via
//!    `HWCAP_CPUID`): on kernels before 4.11, `MRS Xt, ID_AA64*_EL1` /
//!    `MIDR_EL1` / `REVIDR_EL1` traps with `SIGILL`. Catching `SIGILL` and
//!    returning 0 (no optional features advertised) lets binaries that probe CPU
//!    ID registers without checking `HWCAP_CPUID` continue safely.
//!
//! Note on seccomp: `arm64` gained `SECCOMP_MODE_FILTER` in Linux 3.19, so
//! 3.19–4.10 use cheap `SECCOMP_RET_TRACE` stops (stopping only on `statx` /
//! `getrandom`), while 3.11–3.18 fall back to tracing every syscall via
//! `PTRACE_SYSCALL`.

#![cfg(target_arch = "aarch64")]

use std::{
	collections::{HashMap, HashSet},
	env,
	ffi::CStr,
	process::exit,
	sync::OnceLock,
};

use nix::{
	errno::Errno,
	libc,
	sys::{
		ptrace::{self, AddressType, Options},
		signal::{raise, Signal},
		wait::{waitpid, WaitStatus},
	},
	unistd::{fork, ForkResult, Pid},
};

use crate::Config;

static CONFIG: OnceLock<Config> = OnceLock::new();

pub(crate) fn init(cfg: Config) -> bool {
	CONFIG.set(cfg).is_ok()
}

pub(crate) fn config() -> &'static Config {
	CONFIG.get_or_init(Config::default)
}

fn env_var_with_fallback(primary: &str, fallback: Option<&str>) -> Option<String> {
	env::var(primary)
		.ok()
		.or_else(|| fallback.and_then(|name| env::var(name).ok()))
}

pub(crate) fn debug() -> bool {
	let cfg = config();
	matches!(
		env_var_with_fallback(cfg.env_debug, cfg.env_debug_fallback).as_deref(),
		Some("1")
	)
}

pub(crate) fn debug_all() -> bool {
	let cfg = config();
	matches!(
		env_var_with_fallback(cfg.env_debug_all, cfg.env_debug_all_fallback).as_deref(),
		Some("1")
	)
}

// ELF note types for PTRACE_GETREGSET / PTRACE_SETREGSET on aarch64.
const NT_PRSTATUS: libc::c_ulong = 1;
const NT_ARM_SYSTEM_CALL: libc::c_ulong = 0x404;

// AArch32 execution state bit in `user_pt_regs.pstate` (`PSR_MODE32_BIT`).
const PSR_MODE32_BIT: u64 = 0x10;

// `AUDIT_ARCH_AARCH64` = EM_AARCH64 (183) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

// `statx` / `newfstatat` flag bits (asm-generic; all three exist since 2.6.39).
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const NEWFSTATAT_FLAGS_MASK: u64 = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH;

// AArch64 `svc #0` instruction encoding (little-endian 32-bit word).
const INSN_SVC_0: u32 = 0xd400_0001;

/// Layout of Linux `struct user_pt_regs` on `aarch64` (`arch/arm64/include/uapi/asm/ptrace.h`).
#[repr(C)]
#[derive(Clone, Copy)]
struct UserPtRegs {
	regs: [u64; 31],
	sp: u64,
	pc: u64,
	pstate: u64,
}

impl UserPtRegs {
	fn is_aarch64(&self) -> bool {
		(self.pstate & PSR_MODE32_BIT) == 0
	}
}

fn getregs(pid: Pid) -> Result<UserPtRegs, Errno> {
	let mut regs = UserPtRegs {
		regs: [0; 31],
		sp: 0,
		pc: 0,
		pstate: 0,
	};
	let mut iov = libc::iovec {
		iov_base: (&mut regs as *mut UserPtRegs).cast::<libc::c_void>(),
		iov_len: std::mem::size_of::<UserPtRegs>(),
	};
	let rc = unsafe {
		libc::ptrace(
			libc::PTRACE_GETREGSET as _,
			pid.as_raw() as libc::pid_t,
			NT_PRSTATUS as *mut libc::c_void,
			(&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
		)
	};
	if rc == -1 {
		Err(Errno::last())
	} else {
		Ok(regs)
	}
}

fn setregs(pid: Pid, mut regs: UserPtRegs) -> Result<(), Errno> {
	let mut iov = libc::iovec {
		iov_base: (&mut regs as *mut UserPtRegs).cast::<libc::c_void>(),
		iov_len: std::mem::size_of::<UserPtRegs>(),
	};
	let rc = unsafe {
		libc::ptrace(
			libc::PTRACE_SETREGSET as _,
			pid.as_raw() as libc::pid_t,
			NT_PRSTATUS as *mut libc::c_void,
			(&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
		)
	};
	if rc == -1 {
		Err(Errno::last())
	} else {
		Ok(())
	}
}

/// Set the in-flight syscall number via `PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL)`
/// (Linux >= 3.19). Fails with `EINVAL` on 3.11–3.18.
fn set_syscall_nr(pid: Pid, nr: i32) -> Result<(), Errno> {
	let mut scno = nr;
	let mut iov = libc::iovec {
		iov_base: (&mut scno as *mut i32).cast::<libc::c_void>(),
		iov_len: std::mem::size_of::<i32>(),
	};
	let rc = unsafe {
		libc::ptrace(
			libc::PTRACE_SETREGSET as _,
			pid.as_raw() as libc::pid_t,
			NT_ARM_SYSTEM_CALL as *mut libc::c_void,
			(&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
		)
	};
	if rc == -1 {
		Err(Errno::last())
	} else {
		Ok(())
	}
}

fn not_implemented(rc: libc::c_long) -> bool {
	rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
}

/// Probe once whether the kernel implements `getrandom(2)` (added in 3.17).
fn getrandom_missing() -> bool {
	static MISSING: OnceLock<bool> = OnceLock::new();
	*MISSING.get_or_init(|| {
		const GRND_NONBLOCK: libc::c_long = 0x0001;
		let mut buf = [0u8; 16];
		let rc = unsafe {
			libc::syscall(
				libc::SYS_getrandom,
				buf.as_mut_ptr(),
				buf.len(),
				GRND_NONBLOCK,
			)
		};
		not_implemented(rc)
	})
}

/// Probe once whether the kernel implements `statx(2)` (added in 4.11).
fn statx_missing() -> bool {
	static MISSING: OnceLock<bool> = OnceLock::new();
	*MISSING.get_or_init(|| {
		let mut stx = [0u8; 256];
		let path = b"/\0";
		let rc = unsafe {
			libc::syscall(
				libc::SYS_statx,
				libc::AT_FDCWD,
				path.as_ptr(),
				0i32,
				0u32,
				stx.as_mut_ptr() as *mut libc::c_void,
			)
		};
		not_implemented(rc)
	})
}

/// Probe once whether `PR_SET_NO_NEW_PRIVS` breaks `execve` on this kernel.
fn nnp_exec_broken() -> bool {
	static BROKEN: OnceLock<bool> = OnceLock::new();
	*BROKEN.get_or_init(|| {
		use std::os::unix::process::CommandExt;
		let mut cmd = std::process::Command::new("/proc/self/exe");
		if let Some(arg0) = std::env::args_os().next() {
			cmd.arg0(arg0);
		}
		cmd.arg(config().nnp_probe_flag);
		unsafe {
			cmd.pre_exec(|| {
				libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
				Ok(())
			});
		}
		match cmd.status() {
			Ok(status) => !status.success(),
			Err(err) => err.raw_os_error() == Some(libc::EPERM),
		}
	})
}

pub(crate) fn kernel_lt(want_major: u64, want_minor: u64, want_patch: u64) -> bool {
	let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
	if unsafe { libc::uname(&mut uts) } != 0 {
		return false;
	}
	let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
	let mut parts = release.split(|c: char| !c.is_ascii_digit());
	let a = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	let b = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	let c = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	(a, b, c) < (want_major, want_minor, want_patch)
}

/// Whether this process is already running under an active compatibility
/// layer (`OLD_KERNEL_COMPAT_ACTIVE=1`).
pub fn is_active() -> bool {
	matches!(env::var(crate::ENV_ACTIVE).as_deref(), Ok("1"))
}

/// Whether the compatibility tracer should run for this launch.
pub fn enabled() -> bool {
	if is_active() {
		return false;
	}
	let cfg = config();
	match env_var_with_fallback(cfg.env_enable, cfg.env_enable_fallback).as_deref() {
		Some("0") => false,
		Some(_) => true,
		None => needs_compat(),
	}
}

/// Auto mode: enable on kernels older than 4.0 or when `statx` (4.11) is
/// missing.
fn needs_compat() -> bool {
	if kernel_lt(4, 0, 0) {
		return true;
	}
	statx_missing()
}

/// Run an arbitrary command under the tracer. Never returns; `args[0]` is
/// looked up in `PATH`.
pub fn run_command_traced(args: &[String]) -> ! {
	let prefix = config().log_prefix;
	if args.is_empty() {
		eprintln!("{prefix} no command specified");
		exit(1);
	}
	let launch = || {
		let err = std::os::unix::process::CommandExt::exec(
			std::process::Command::new(&args[0]).args(&args[1..]),
		);
		eprintln!("{prefix} failed to execute {}: {err}", args[0]);
		exit(127)
	};
	if !enabled() {
		launch()
	}
	run_traced(&launch)
}

/// Fork a tracer supervisor in the parent (which never returns) and return in
/// the traced child so the caller continues under the compatibility layer.
pub fn enter_traced() {
	let prefix = config().log_prefix;
	if is_active() {
		return;
	}
	if !ptrace_permitted() {
		eprintln!("{prefix} ptrace unavailable, running without old kernel compatibility");
		return;
	}

	let _ = nnp_exec_broken();

	let mut pipe_fds = [0i32; 2];
	let have_pipe = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } == 0;

	match unsafe { fork() } {
		Ok(ForkResult::Child) => {
			if have_pipe {
				unsafe { libc::close(pipe_fds[0]) };
			}
			if ptrace::traceme().is_err() {
				if have_pipe {
					unsafe { libc::close(pipe_fds[1]) };
				}
				return;
			}
			let seccomp = install_seccomp_filter();
			if have_pipe {
				let byte = [u8::from(seccomp)];
				unsafe {
					libc::write(pipe_fds[1], byte.as_ptr() as *const libc::c_void, 1);
					libc::close(pipe_fds[1]);
				}
			}
			env::set_var(crate::ENV_ACTIVE, "1");
			let _ = raise(Signal::SIGSTOP);
		}
		Ok(ForkResult::Parent { child }) => {
			let mut use_seccomp = false;
			if have_pipe {
				unsafe { libc::close(pipe_fds[1]) };
				let mut byte = [0u8; 1];
				let n = unsafe {
					libc::read(pipe_fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1)
				};
				use_seccomp = n == 1 && byte[0] == 1;
				unsafe { libc::close(pipe_fds[0]) };
			}
			eprintln!("{prefix} enabled old kernel compatibility mode");
			supervise(child, use_seccomp)
		}
		Err(_) => {}
	}
}

/// Fork, trace the child and let it call `launch`, which must not return.
pub fn run_traced(launch: &dyn Fn()) -> ! {
	enter_traced();
	launch();
	exit(1)
}

fn ptrace_permitted() -> bool {
	match unsafe { fork() } {
		Ok(ForkResult::Child) => {
			let ok = ptrace::traceme().is_ok();
			exit(if ok { 0 } else { 1 })
		}
		Ok(ForkResult::Parent { child }) => {
			matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
		}
		Err(_) => false,
	}
}

/// Install a seccomp-bpf filter that stops (`SECCOMP_RET_TRACE`) only on the
/// syscalls this kernel lacks (`statx`, `getrandom`). Requires Linux 3.19+ on
/// `arm64`; older kernels return `false` and fall back to tracing every
/// syscall.
fn install_seccomp_filter() -> bool {
	if nnp_exec_broken() {
		if debug() {
			eprintln!("kernel-compat: seccomp unusable (no_new_privs breaks execve)");
		}
		return false;
	}
	const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
	const BPF_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
	const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
	let stmt = |code: u16, k: u32| libc::sock_filter {
		code,
		jt: 0,
		jf: 0,
		k,
	};
	let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter {
		code: BPF_JEQ_K,
		jt,
		jf,
		k,
	};

	let mut wanted: Vec<u32> = Vec::new();
	if statx_missing() {
		wanted.push(libc::SYS_statx as u32);
	}
	if getrandom_missing() {
		wanted.push(libc::SYS_getrandom as u32);
	}
	let n = wanted.len();
	let mut filter: Vec<libc::sock_filter> = Vec::with_capacity(6 + n);
	filter.push(stmt(BPF_LD_W_ABS, 4)); // seccomp_data.arch
	filter.push(jump(AUDIT_ARCH_AARCH64, 1, 0));
	filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
	filter.push(stmt(BPF_LD_W_ABS, 0)); // seccomp_data.nr
	for (i, nr) in wanted.iter().enumerate() {
		filter.push(jump(*nr, (n - i) as u8, 0));
	}
	filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
	if n > 0 {
		filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_TRACE));
	}

	let prog = libc::sock_fprog {
		len: filter.len() as u16,
		filter: filter.as_ptr() as *mut libc::sock_filter,
	};
	if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
		return false;
	}
	let rc = unsafe {
		libc::prctl(
			libc::PR_SET_SECCOMP,
			libc::SECCOMP_MODE_FILTER,
			&prog as *const _ as libc::c_ulong,
		)
	};
	rc == 0
}

fn install_options(pid: Pid, wanted: &[Options]) -> Options {
	let mut acc = Options::empty();
	for &opt in wanted {
		if ptrace::setoptions(pid, acc | opt).is_ok() {
			acc |= opt;
		} else {
			let _ = ptrace::setoptions(pid, acc);
			if debug() {
				eprintln!("kernel-compat: option {:?} unsupported, skipped", opt);
			}
		}
	}
	acc
}

fn tracer_options(seccomp: bool) -> Vec<Options> {
	let mut opts = vec![
		Options::PTRACE_O_TRACESYSGOOD,
		Options::PTRACE_O_TRACEFORK,
		Options::PTRACE_O_TRACEVFORK,
		Options::PTRACE_O_TRACECLONE,
		Options::PTRACE_O_TRACEEXEC,
	];
	if seccomp {
		opts.push(Options::PTRACE_O_TRACESECCOMP);
	}
	opts
}

enum Wait {
	Exited(Pid, i32),
	Signaled(Pid, i32),
	Stopped(Pid, i32),
	Event(Pid, u32),
	Syscall(Pid),
}

fn wait_any() -> Result<Wait, Errno> {
	let mut status: libc::c_int = 0;
	let rc = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
	if rc < 0 {
		return Err(Errno::last());
	}
	let pid = Pid::from_raw(rc);
	let s = status;
	if s & 0x7f == 0 {
		Ok(Wait::Exited(pid, (s >> 8) & 0xff))
	} else if s & 0xff == 0x7f {
		let sig = (s >> 8) & 0xff;
		if sig & 0x80 != 0 {
			Ok(Wait::Syscall(pid))
		} else {
			let event = (s >> 16) as u32;
			if event != 0 {
				Ok(Wait::Event(pid, event))
			} else {
				Ok(Wait::Stopped(pid, sig))
			}
		}
	} else {
		Ok(Wait::Signaled(pid, s & 0x7f))
	}
}

fn ptrace_resume(request: libc::c_uint, pid: Pid, sig: Option<i32>) -> Result<(), ()> {
	let rc = unsafe {
		libc::ptrace(
			request as _,
			pid.as_raw() as libc::pid_t,
			std::ptr::null_mut::<libc::c_void>(),
			sig.unwrap_or(0) as *mut libc::c_void,
		)
	};
	if rc == -1 {
		Err(())
	} else {
		Ok(())
	}
}

struct StatxState {
	statxbuf: u64,
	scratch: u64,
	/// Original argument registers (`x1`, `x2`, `x3`, `x8`) to restore on exit
	/// so `statx` leaves caller-visible registers intact just like the kernel.
	saved_x1: u64,
	saved_x2: u64,
	saved_x3: u64,
	saved_x8: u64,
}

/// Captured arguments of an in-flight `getrandom` or `statx` syscall, since on
/// `aarch64` the return value overwrites `x0` (`buf` / `dirfd`).
struct PendingGetrandom {
	buf: u64,
	count: usize,
}

/// For Linux 3.11–3.18 where `NT_ARM_SYSTEM_CALL` does not exist: after `statx`
/// fails with `-ENOSYS`, we rewind `pc` to the `svc #0` instruction and run
/// `newfstatat`/`fstat` as a follow-up syscall, then restore `saved` with the
/// translated result.
struct StatxReplay {
	saved: UserPtRegs,
	statxbuf: u64,
	scratch: u64,
	at_entry: bool,
}

struct Tracer {
	child: Pid,
	configured: HashSet<Pid>,
	in_syscall: HashMap<Pid, bool>,
	last_syscall: HashMap<Pid, u64>,
	/// In-place `statx` rewrite (Linux >= 3.19 with `NT_ARM_SYSTEM_CALL`).
	statx: HashMap<Pid, StatxState>,
	/// Saved `statx` entry regs for pre-3.19 replay when `NT_ARM_SYSTEM_CALL` is
	/// unsupported.
	statx_deferred: HashMap<Pid, UserPtRegs>,
	/// Active pre-3.19 `statx` replay syscall in flight.
	statx_replay: HashMap<Pid, StatxReplay>,
	/// Signal held back while a pre-3.19 `statx` replay is in flight.
	stashed_signal: HashMap<Pid, i32>,
	/// Saved `getrandom(buf, count, flags)` args for syscall-exit completion.
	getrandom: HashMap<Pid, PendingGetrandom>,
	/// `sp` to restore at syscall exit for in-place scratch reservations.
	reserved: HashMap<Pid, u64>,
	/// Pids resumed from a seccomp stop with `PTRACE_SYSCALL` whose entry stop
	/// still needs to be skipped.
	expect_entry: HashSet<Pid>,
	/// True on Linux 3.19–4.7 where `secure_computing()` runs *before*
	/// `tracehook_report_syscall(ENTER)`, so resuming a `PTRACE_EVENT_SECCOMP`
	/// stop with `PTRACE_SYSCALL` produces an extra syscall-entry stop before
	/// the syscall-exit stop. False on Linux >= 4.8 where `secure_computing()`
	/// runs *after* `PTRACE_SYSCALL_ENTER` (the next stop is directly the exit).
	seccomp_emits_entry: bool,
	syscall_mode: bool,
	seccomp_mode: bool,
	main_code: Option<i32>,
}

impl Tracer {
	fn resume(&self, pid: Pid, sig: Option<i32>) {
		let request = if self.syscall_mode {
			libc::PTRACE_SYSCALL as libc::c_uint
		} else {
			libc::PTRACE_CONT as libc::c_uint
		};
		let _ = ptrace_resume(request, pid, sig);
	}

	fn resume_syscall(&self, pid: Pid, sig: Option<i32>) {
		let _ = ptrace_resume(libc::PTRACE_SYSCALL as libc::c_uint, pid, sig);
	}

	fn forget(&mut self, pid: Pid) {
		self.configured.remove(&pid);
		self.in_syscall.remove(&pid);
		self.last_syscall.remove(&pid);
		self.statx.remove(&pid);
		self.statx_deferred.remove(&pid);
		self.statx_replay.remove(&pid);
		self.stashed_signal.remove(&pid);
		self.getrandom.remove(&pid);
		self.reserved.remove(&pid);
		self.expect_entry.remove(&pid);
	}

	fn supervise(&mut self) -> ! {
		if debug() {
			eprintln!(
				"kernel-compat: mode {}",
				if self.seccomp_mode {
					"seccomp (only translated syscalls)"
				} else if self.syscall_mode {
					"ptrace (every syscall)"
				} else {
					"signals only"
				}
			);
		}
		self.resume(self.child, None);

		loop {
			match wait_any() {
				Ok(Wait::Exited(pid, code)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} exited {code}");
					}
					self.forget(pid);
					if pid == self.child {
						if self.seccomp_mode {
							self.main_code = Some(code);
						} else {
							exit(code);
						}
					}
				}
				Ok(Wait::Signaled(pid, sig)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} killed by {sig:?}");
					}
					self.forget(pid);
					if pid == self.child {
						if self.seccomp_mode {
							self.main_code = Some(128 + sig);
						} else {
							exit(128 + sig);
						}
					}
				}
				Ok(Wait::Stopped(pid, sig)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} stopped: {sig:?}");
					}
					if pid != self.child && !self.configured.contains(&pid) {
						install_options(pid, &tracer_options(self.seccomp_mode));
						self.configured.insert(pid);
						if sig == libc::SIGSTOP {
							self.resume(pid, None);
							continue;
						}
					}
					// Hold signals while a pre-3.19 `statx` replay syscall is in
					// flight so application handlers cannot run with our rewritten
					// registers.
					if self.statx_replay.contains_key(&pid)
						&& sig != 0
						&& sig != libc::SIGSTOP
						&& sig != libc::SIGTRAP
					{
						self.stashed_signal.insert(pid, sig);
						self.resume(pid, None);
						continue;
					}
					let pending = self.seccomp_mode
						&& (self.reserved.contains_key(&pid)
							|| self.expect_entry.contains(&pid)
							|| self.statx.contains_key(&pid)
							|| self.getrandom.contains_key(&pid));
					let suppress = sig == libc::SIGILL && emulate_sigill(pid);
					if pending {
						self.resume_syscall(pid, if suppress { None } else { Some(sig) });
					} else if suppress {
						self.resume(pid, None);
					} else {
						self.resume(pid, Some(sig));
					}
				}
				Ok(Wait::Event(pid, event)) if event == libc::PTRACE_EVENT_SECCOMP as u32 => {
					if self.on_seccomp_stop(pid) {
						if self.seccomp_emits_entry {
							self.expect_entry.insert(pid);
						}
						self.resume_syscall(pid, None);
					} else {
						self.resume(pid, None);
					}
				}
				Ok(Wait::Event(pid, event)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} event {event}");
					}
					self.resume(pid, None);
				}
				Ok(Wait::Syscall(pid)) => {
					if self.seccomp_mode {
						if self.expect_entry.remove(&pid) {
							self.resume_syscall(pid, None);
						} else {
							self.on_syscall_exit(pid);
							self.resume(pid, None);
						}
					} else if self.statx_replay.contains_key(&pid) {
						self.step_statx_replay(pid);
						if !self.statx_replay.contains_key(&pid) {
							if let Some(sig) = self.stashed_signal.remove(&pid) {
								self.resume(pid, Some(sig));
								continue;
							}
						}
						self.resume(pid, None);
					} else {
						self.on_syscall_stop(pid);
						self.resume(pid, None);
					}
				}
				Err(Errno::ECHILD) => exit(self.main_code.unwrap_or(0)),
				Err(err) => {
					if debug() {
						eprintln!("kernel-compat: waitpid error: {err}");
					}
				}
			}
		}
	}

	/// Handle a `SECCOMP_RET_TRACE` stop (Linux >= 3.19).
	fn on_seccomp_stop(&mut self, pid: Pid) -> bool {
		let Ok(regs) = getregs(pid) else {
			return false;
		};
		if !regs.is_aarch64() {
			return false;
		}
		let nr = regs.regs[8];
		if nr == libc::SYS_statx as u64 && statx_missing() {
			return self.setup_statx_inplace(pid, regs);
		}
		if nr == libc::SYS_getrandom as u64 && getrandom_missing() {
			self.getrandom.insert(
				pid,
				PendingGetrandom {
					buf: regs.regs[0],
					count: regs.regs[1] as usize,
				},
			);
			return true;
		}
		false
	}

	fn on_syscall_stop(&mut self, pid: Pid) {
		let entering = !*self.in_syscall.get(&pid).unwrap_or(&false);
		self.in_syscall.insert(pid, entering);

		if entering {
			let Ok(regs) = getregs(pid) else {
				return;
			};
			if !regs.is_aarch64() {
				return;
			}
			let nr = regs.regs[8];
			self.last_syscall.insert(pid, nr);

			if nr == libc::SYS_statx as u64 && statx_missing() {
				if !self.setup_statx_inplace(pid, regs) && regs.regs[4] != 0 {
					// Linux 3.11–3.18 lacks NT_ARM_SYSTEM_CALL: wait for the
					// kernel's -ENOSYS exit, then replay via `svc #0`.
					self.statx_deferred.insert(pid, regs);
				}
			} else if nr == libc::SYS_getrandom as u64 && getrandom_missing() {
				self.getrandom.insert(
					pid,
					PendingGetrandom {
						buf: regs.regs[0],
						count: regs.regs[1] as usize,
					},
				);
			}
		} else {
			self.on_syscall_exit(pid);
		}
	}

	fn on_syscall_exit(&mut self, pid: Pid) {
		let mut regs = match getregs(pid) {
			Ok(regs) => regs,
			Err(_) => {
				self.statx.remove(&pid);
				self.statx_deferred.remove(&pid);
				self.getrandom.remove(&pid);
				self.last_syscall.remove(&pid);
				self.reserved.remove(&pid);
				return;
			}
		};
		if !regs.is_aarch64() {
			return;
		}
		if debug_all() {
			eprintln!(
				"kernel-compat: [t{pid}] syscall {} -> {}",
				self.last_syscall.get(&pid).copied().unwrap_or(0),
				regs.regs[0] as i64
			);
		}

		// Pre-3.19 deferred `statx`: if the kernel returned -ENOSYS, rewind
		// `pc` to `svc #0` and run `newfstatat` / `fstat` as a follow-up call.
		if let Some(saved) = self.statx_deferred.remove(&pid) {
			if regs.regs[0] == (-(libc::ENOSYS as i64)) as u64
				&& self.start_statx_replay(pid, saved, regs)
			{
				self.last_syscall.remove(&pid);
				return;
			}
		}

		let mut dirty = false;
		if let Some(state) = self.statx.remove(&pid) {
			regs.regs[1] = state.saved_x1;
			regs.regs[2] = state.saved_x2;
			regs.regs[3] = state.saved_x3;
			regs.regs[8] = state.saved_x8;
			dirty = true;
			if regs.regs[0] == 0 {
				let ok = read_struct(pid, state.scratch, 128)
					.map(|stat| build_statx(&stat))
					.map(|stx| write_struct(pid, state.statxbuf, &stx))
					.unwrap_or(false);
				if ok {
					if debug() {
						eprintln!("kernel-compat: statx ok");
					}
				} else {
					regs.regs[0] = (-(libc::EFAULT as i64)) as u64;
				}
			} else if debug() {
				eprintln!(
					"kernel-compat: statx -> fallback ret={} (errno {})",
					regs.regs[0] as i64,
					-(regs.regs[0] as i64)
				);
			}
		}

		if let Some(saved_sp) = self.reserved.remove(&pid) {
			regs.sp = saved_sp;
			dirty = true;
		}

		if let Some(req) = self.getrandom.remove(&pid) {
			if emulate_getrandom(pid, req.buf, req.count) {
				if debug() {
					eprintln!(
						"kernel-compat: getrandom emulated ({} bytes at {:#x})",
						req.count, req.buf
					);
				}
				regs.regs[0] = req.count as u64;
				dirty = true;
			}
		}

		if dirty {
			let _ = setregs(pid, regs);
		}
		if debug() && regs.regs[0] == (-(libc::ENOSYS as i64)) as u64 {
			let nr = self.last_syscall.get(&pid).copied().unwrap_or(0);
			eprintln!("kernel-compat: pid {pid} syscall {nr} -> ENOSYS");
		}
		self.last_syscall.remove(&pid);
	}

	/// In-place `statx` -> `newfstatat` / `fstat` rewrite using
	/// `NT_ARM_SYSTEM_CALL` (Linux >= 3.19). Returns `false` if the kernel
	/// rejects `NT_ARM_SYSTEM_CALL` (Linux 3.11–3.18) or `statxbuf == 0`.
	fn setup_statx_inplace(&mut self, pid: Pid, mut regs: UserPtRegs) -> bool {
		let statxbuf = regs.regs[4];
		if statxbuf == 0 {
			return false;
		}
		// statx(dirfd(x0), path(x1), flags(x2), mask(x3), statxbuf(x4))
		let saved_sp = regs.sp;
		let saved_x1 = regs.regs[1];
		let saved_x2 = regs.regs[2];
		let saved_x3 = regs.regs[3];
		let saved_x8 = regs.regs[8];
		let scratch = (saved_sp.wrapping_sub(512)) & !0xf;
		let empty_path = (regs.regs[2] & AT_EMPTY_PATH != 0)
			&& (regs.regs[1] == 0 || peek_byte(pid, regs.regs[1]) == Some(0));
		let new_nr: i32 = if empty_path {
			libc::SYS_fstat as i32
		} else {
			libc::SYS_newfstatat as i32
		};
		// Try changing the syscall number first so we leave registers untouched
		// on Linux 3.11–3.18 where NT_ARM_SYSTEM_CALL returns EINVAL.
		if set_syscall_nr(pid, new_nr).is_err() {
			return false;
		}
		if debug() {
			eprintln!(
				"kernel-compat: statx path='{}' flags={:#x}",
				read_cstr(pid, regs.regs[1]),
				regs.regs[2]
			);
		}
		regs.sp = scratch;
		if new_nr == libc::SYS_fstat as i32 {
			// fstat(fd(x0), statbuf(x1))
			regs.regs[1] = scratch;
			regs.regs[2] = 0;
		} else {
			// newfstatat(dirfd(x0), path(x1), statbuf(x2), flags(x3))
			regs.regs[3] = regs.regs[2] & NEWFSTATAT_FLAGS_MASK;
			regs.regs[2] = scratch;
		}
		regs.regs[8] = new_nr as u64;
		if setregs(pid, regs).is_err() {
			return false;
		}
		self.reserved.insert(pid, saved_sp);
		self.statx.insert(
			pid,
			StatxState {
				statxbuf,
				scratch,
				saved_x1,
				saved_x2,
				saved_x3,
				saved_x8,
			},
		);
		true
	}

	/// Pre-3.19 fallback when `NT_ARM_SYSTEM_CALL` is unavailable: verify the
	/// instruction behind `pc` is `svc #0`, back up `pc` by 4, and issue
	/// `newfstatat` or `fstat` with `x8` set to the fallback syscall number.
	fn start_statx_replay(&mut self, pid: Pid, saved: UserPtRegs, exit_regs: UserPtRegs) -> bool {
		let statxbuf = saved.regs[4];
		if statxbuf == 0 {
			return false;
		}
		let svc_pc = exit_regs.pc.wrapping_sub(4);
		let Some(insn) = peek_u32(pid, svc_pc) else {
			return false;
		};
		if insn != INSN_SVC_0 {
			if debug() {
				eprintln!(
					"kernel-compat: no svc #0 behind {:#x} (got {insn:#x}), cannot replay statx",
					exit_regs.pc
				);
			}
			return false;
		}

		let scratch = (saved.sp.wrapping_sub(512)) & !0xf;
		let empty_path = (saved.regs[2] & AT_EMPTY_PATH != 0)
			&& (saved.regs[1] == 0 || peek_byte(pid, saved.regs[1]) == Some(0));
		let mut replay = saved;
		replay.pc = svc_pc;
		replay.sp = scratch;
		if empty_path {
			replay.regs[8] = libc::SYS_fstat as u64;
			replay.regs[1] = scratch;
			replay.regs[2] = 0;
		} else {
			replay.regs[8] = libc::SYS_newfstatat as u64;
			replay.regs[3] = saved.regs[2] & NEWFSTATAT_FLAGS_MASK;
			replay.regs[2] = scratch;
		}
		if setregs(pid, replay).is_err() {
			return false;
		}
		if debug() {
			eprintln!(
				"kernel-compat: statx replayed via svc #0 (buf {statxbuf:#x})"
			);
		}
		self.statx_replay.insert(
			pid,
			StatxReplay {
				saved: UserPtRegs {
					pc: exit_regs.pc,
					..saved
				},
				statxbuf,
				scratch,
				at_entry: true,
			},
		);
		true
	}

	fn step_statx_replay(&mut self, pid: Pid) {
		let Some(mut state) = self.statx_replay.remove(&pid) else {
			return;
		};
		if state.at_entry {
			state.at_entry = false;
			self.statx_replay.insert(pid, state);
			return;
		}
		let Ok(exit_regs) = getregs(pid) else {
			return;
		};
		let mut done = state.saved;
		if exit_regs.regs[0] == 0 {
			let ok = read_struct(pid, state.scratch, 128)
				.map(|stat| build_statx(&stat))
				.map(|stx| write_struct(pid, state.statxbuf, &stx))
				.unwrap_or(false);
			if ok {
				done.regs[0] = 0;
				if debug() {
					eprintln!("kernel-compat: statx replay ok");
				}
			} else {
				done.regs[0] = (-(libc::EFAULT as i64)) as u64;
			}
		} else {
			done.regs[0] = exit_regs.regs[0];
			if debug() {
				eprintln!(
					"kernel-compat: statx replay ret={} (errno {})",
					exit_regs.regs[0] as i64,
					-(exit_regs.regs[0] as i64)
				);
			}
		}
		let _ = setregs(pid, done);
	}
}

/// Emulate trapped `MRS Xt, <sysreg>` for EL1 CPU ID registers (`Op0=3, Op1=0,
/// CRn=0, CRm in {0, 4..=7}`), which kernels before 4.11 do not emulate in the
/// kernel (`HWCAP_CPUID`). Returning 0 reports no optional extensions and
/// advances `pc` by 4.
fn emulate_sigill(pid: Pid) -> bool {
	let Ok(mut regs) = getregs(pid) else {
		return false;
	};
	if !regs.is_aarch64() {
		return false;
	}
	let Some(insn) = peek_u32(pid, regs.pc) else {
		return false;
	};
	if debug() {
		eprintln!(
			"kernel-compat: SIGILL at {:#x} insn={insn:#010x}",
			regs.pc
		);
	}
	let Some((rt, op0, op1, crn, crm, op2)) = decode_emulated_mrs(insn) else {
		return false;
	};
	// rt == 31 is XZR (writes discarded).
	if rt < 31 {
		regs.regs[rt] = 0;
	}
	regs.pc = regs.pc.wrapping_add(4);
	if setregs(pid, regs).is_err() {
		return false;
	}
	if debug() {
		eprintln!(
			"kernel-compat: emulated MRS x{rt}, S{op0}_{op1}_C{crn}_C{crm}_{op2} -> 0"
		);
	}
	true
}

/// Decode an `MRS Xt, <sysreg>` instruction that targets the EL1 CPU ID space
/// (`Op0=3, Op1=0, CRn=0, CRm in {0, 4..=7}`). Returns `(rt, op0, op1, crn, crm, op2)`.
fn decode_emulated_mrs(insn: u32) -> Option<(usize, u32, u32, u32, u32, u32)> {
	// MRS encoding: 1101_0101_0011_xxxx_xxxx_xxxx_xxx_ttttt
	if (insn & 0xfff0_0000) != 0xd530_0000 {
		return None;
	}
	let op0 = 2 | ((insn >> 19) & 1);
	let op1 = (insn >> 16) & 0x7;
	let crn = (insn >> 12) & 0xf;
	let crm = (insn >> 8) & 0xf;
	let op2 = (insn >> 5) & 0x7;
	let rt = (insn & 0x1f) as usize;
	let is_id_sysreg = op0 == 3 && op1 == 0 && crn == 0 && (crm == 0 || (4..=7).contains(&crm));
	is_id_sysreg.then_some((rt, op0, op1, crn, crm, op2))
}

fn peek_word(pid: Pid, addr: u64) -> Option<u64> {
	ptrace::read(pid, addr as AddressType).ok().map(|w| w as u64)
}

fn peek_byte(pid: Pid, addr: u64) -> Option<u8> {
	let word = peek_word(pid, addr & !7)?;
	Some(((word >> (8 * (addr & 7))) & 0xff) as u8)
}

/// Read a little-endian 32-bit instruction at `addr` without crossing an 8-byte
/// word boundary (so a 4-byte instruction at `page_end - 4` never reads past
/// the page).
fn peek_u32(pid: Pid, addr: u64) -> Option<u32> {
	let word = peek_word(pid, addr & !7)?;
	let shift = 8 * (addr & 4);
	Some(((word >> shift) & 0xffff_ffff) as u32)
}

#[allow(deprecated)]
fn poke_word(pid: Pid, addr: u64, val: u64) -> bool {
	ptrace::write(pid, addr as AddressType, val as i64).is_ok()
}

fn read_cstr(pid: Pid, addr: u64) -> String {
	if addr == 0 {
		return String::new();
	}
	let mut out = Vec::new();
	let mut off = 0u64;
	'outer: while out.len() < 256 {
		let Some(word) = peek_word(pid, addr + off) else {
			break;
		};
		for i in 0..8 {
			let b = ((word >> (8 * i)) & 0xff) as u8;
			if b == 0 {
				break 'outer;
			}
			out.push(b);
		}
		off += 8;
	}
	String::from_utf8_lossy(&out).into_owned()
}

fn read_struct(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(len + 8);
	let mut off = 0u64;
	while out.len() < len {
		let word = peek_word(pid, addr + off)?;
		out.extend_from_slice(&word.to_le_bytes());
		off += 8;
	}
	out.truncate(len);
	Some(out)
}

fn write_struct(pid: Pid, addr: u64, bytes: &[u8]) -> bool {
	let mut off = 0usize;
	while off < bytes.len() {
		let n = (bytes.len() - off).min(8);
		let at = addr + off as u64;
		let mut chunk = if n == 8 {
			[0u8; 8]
		} else {
			peek_word(pid, at).unwrap_or(0).to_le_bytes()
		};
		chunk[..n].copy_from_slice(&bytes[off..off + n]);
		if !poke_word(pid, at, u64::from_le_bytes(chunk)) {
			return false;
		}
		off += 8;
	}
	true
}

fn emulate_getrandom(pid: Pid, buf: u64, count: usize) -> bool {
	if count == 0 {
		return true;
	}
	if buf == 0 {
		return false;
	}
	use std::io::Read;
	let mut file = match std::fs::File::open("/dev/urandom") {
		Ok(file) => file,
		Err(_) => return false,
	};
	const CHUNK: usize = 64 * 1024;
	let mut chunk = vec![0u8; count.min(CHUNK)];
	let mut off = 0usize;
	while off < count {
		let want = (count - off).min(CHUNK);
		let dst = &mut chunk[..want];
		if file.read_exact(dst).is_err() {
			return false;
		}
		if !write_struct(pid, buf + off as u64, dst) {
			return false;
		}
		off += want;
	}
	true
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
	u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or_default())
}

fn rd_u64(b: &[u8], o: usize) -> u64 {
	u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default())
}

fn wr_u32(b: &mut [u8], o: usize, v: u32) {
	b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn wr_u64(b: &mut [u8], o: usize, v: u64) {
	b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn dev_major(dev: u64) -> u32 {
	(((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64)) as u32
}

fn dev_minor(dev: u64) -> u32 {
	((dev & 0xff) | ((dev >> 12) & !0xffu64)) as u32
}

/// `struct stat` (`include/uapi/asm-generic/stat.h`, 64-bit little-endian,
/// 128 bytes) -> `struct statx` (256 bytes).
fn build_statx(stat: &[u8]) -> Vec<u8> {
	const STATX_BASIC_STATS: u32 = 0x7ff;
	let mut s = vec![0u8; 256];
	let st_dev = rd_u64(stat, 0);
	let st_ino = rd_u64(stat, 8);
	let st_mode = rd_u32(stat, 16);
	let st_nlink = rd_u32(stat, 20);
	let st_uid = rd_u32(stat, 24);
	let st_gid = rd_u32(stat, 28);
	let st_rdev = rd_u64(stat, 32);
	// offset 40..48: __pad1
	let st_size = rd_u64(stat, 48);
	let st_blksize = rd_u32(stat, 56);
	// offset 60..64: __pad2
	let st_blocks = rd_u64(stat, 64);
	let atime_s = rd_u64(stat, 72);
	let atime_ns = rd_u64(stat, 80);
	let mtime_s = rd_u64(stat, 88);
	let mtime_ns = rd_u64(stat, 96);
	let ctime_s = rd_u64(stat, 104);
	let ctime_ns = rd_u64(stat, 112);

	wr_u32(&mut s, 0, STATX_BASIC_STATS);
	wr_u32(&mut s, 4, st_blksize);
	wr_u32(&mut s, 16, st_nlink);
	wr_u32(&mut s, 20, st_uid);
	wr_u32(&mut s, 24, st_gid);
	s[28..30].copy_from_slice(&(st_mode as u16).to_le_bytes());
	wr_u64(&mut s, 32, st_ino);
	wr_u64(&mut s, 40, st_size);
	wr_u64(&mut s, 48, st_blocks);
	wr_u64(&mut s, 64, atime_s);
	wr_u32(&mut s, 72, atime_ns as u32);
	wr_u64(&mut s, 96, ctime_s);
	wr_u32(&mut s, 104, ctime_ns as u32);
	wr_u64(&mut s, 112, mtime_s);
	wr_u32(&mut s, 120, mtime_ns as u32);
	wr_u32(&mut s, 128, dev_major(st_rdev));
	wr_u32(&mut s, 132, dev_minor(st_rdev));
	wr_u32(&mut s, 136, dev_major(st_dev));
	wr_u32(&mut s, 140, dev_minor(st_dev));
	s
}

fn supervise(child: Pid, use_seccomp: bool) -> ! {
	match waitpid(child, None) {
		Ok(WaitStatus::Stopped(_, _)) => {}
		Ok(WaitStatus::Exited(_, code)) => exit(code),
		Ok(WaitStatus::Signaled(_, sig, _)) => exit(128 + sig as i32),
		_ => {}
	}
	let options = install_options(child, &tracer_options(use_seccomp));
	let seccomp_mode = use_seccomp && options.contains(Options::PTRACE_O_TRACESECCOMP);
	let syscall_mode = !seccomp_mode && options.contains(Options::PTRACE_O_TRACESYSGOOD);
	// On arm64 Linux 3.19–4.7, `secure_computing()` ran before
	// `tracehook_report_syscall(PTRACE_SYSCALL_ENTER)`; starting in Linux 4.8
	// (commit 910cd32e552e / ptrace-before-seccomp), `PTRACE_EVENT_SECCOMP`
	// fires after the entry hook so `PTRACE_SYSCALL` goes straight to exit.
	let seccomp_emits_entry = kernel_lt(4, 8, 0);
	if debug() {
		eprintln!("kernel-compat: active options: {options:?}");
	}
	let mut tracer = Tracer {
		child,
		configured: HashSet::from([child]),
		in_syscall: HashMap::new(),
		last_syscall: HashMap::new(),
		statx: HashMap::new(),
		statx_deferred: HashMap::new(),
		statx_replay: HashMap::new(),
		stashed_signal: HashMap::new(),
		getrandom: HashMap::new(),
		reserved: HashMap::new(),
		expect_entry: HashSet::new(),
		seccomp_emits_entry,
		syscall_mode,
		seccomp_mode,
		main_code: None,
	};
	tracer.supervise()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn build_statx_matches_asm_generic_stat_layout() {
		let mut st = [0u8; 128];
		// st_dev = makedev(8, 1) -> (8 << 8) | 1 = 0x801
		wr_u64(&mut st, 0, 0x801);
		wr_u64(&mut st, 8, 123456);
		wr_u32(&mut st, 16, 0o100644);
		wr_u32(&mut st, 20, 2);
		wr_u32(&mut st, 24, 1000);
		wr_u32(&mut st, 28, 1001);
		wr_u64(&mut st, 32, 0x103); // rdev major=1, minor=3
		wr_u64(&mut st, 48, 4096);
		wr_u32(&mut st, 56, 4096);
		wr_u64(&mut st, 64, 8);
		wr_u64(&mut st, 72, 1700000001);
		wr_u64(&mut st, 80, 111);
		wr_u64(&mut st, 88, 1700000002);
		wr_u64(&mut st, 96, 222);
		wr_u64(&mut st, 104, 1700000003);
		wr_u64(&mut st, 112, 333);

		let stx = build_statx(&st);
		assert_eq!(stx.len(), 256);
		assert_eq!(rd_u32(&stx, 0), 0x7ff);
		assert_eq!(rd_u32(&stx, 4), 4096);
		assert_eq!(rd_u32(&stx, 16), 2);
		assert_eq!(rd_u32(&stx, 20), 1000);
		assert_eq!(rd_u32(&stx, 24), 1001);
		assert_eq!(u16::from_le_bytes([stx[28], stx[29]]), 0o100644);
		assert_eq!(rd_u64(&stx, 32), 123456);
		assert_eq!(rd_u64(&stx, 40), 4096);
		assert_eq!(rd_u64(&stx, 48), 8);
		assert_eq!(rd_u64(&stx, 64), 1700000001);
		assert_eq!(rd_u32(&stx, 72), 111);
		assert_eq!(rd_u64(&stx, 96), 1700000003);
		assert_eq!(rd_u32(&stx, 104), 333);
		assert_eq!(rd_u64(&stx, 112), 1700000002);
		assert_eq!(rd_u32(&stx, 120), 222);
		assert_eq!(rd_u32(&stx, 128), 1);
		assert_eq!(rd_u32(&stx, 132), 3);
		assert_eq!(rd_u32(&stx, 136), 8);
		assert_eq!(rd_u32(&stx, 140), 1);
	}

	#[test]
	fn decode_emulated_mrs_recognizes_id_registers_only() {
		// mrs x0, midr_el1 (op0=3, op1=0, crn=0, crm=0, op2=0, rt=0) -> 0xd5380000
		assert_eq!(decode_emulated_mrs(0xd538_0000), Some((0, 3, 0, 0, 0, 0)));
		// mrs x5, id_aa64isar0_el1 (op0=3, op1=0, crn=0, crm=6, op2=0, rt=5) -> 0xd5380605
		assert_eq!(decode_emulated_mrs(0xd538_0605), Some((5, 3, 0, 0, 6, 0)));
		// mrs x30, id_aa64pfr0_el1 (op0=3, op1=0, crn=0, crm=4, op2=0, rt=30) -> 0xd538041e
		assert_eq!(decode_emulated_mrs(0xd538_041e), Some((30, 3, 0, 0, 4, 0)));
		// mrs x0, cntvct_el0 (op0=3, op1=3, crn=14, crm=0, op2=2) -> not an ID reg
		assert_eq!(decode_emulated_mrs(0xd53b_e040), None);
		// svc #0 -> not an MRS
		assert_eq!(decode_emulated_mrs(INSN_SVC_0), None);
		// udf #0 -> not an MRS
		assert_eq!(decode_emulated_mrs(0x0000_0000), None);
	}
}
