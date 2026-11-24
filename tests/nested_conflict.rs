#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;
use std::process::Command;

fn example_bin(name: &str) -> PathBuf {
	let target_dir = std::env::var_os("CARGO_TARGET_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
	let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
	let bin = target_dir.join(profile).join("examples").join(name);
	if bin.exists() {
		return bin;
	}
	// Fallback: walk up from current_exe looking for an `examples/<name>` sibling.
	if let Ok(exe) = std::env::current_exe() {
		for ancestor in exe.ancestors().skip(1) {
			let candidate = ancestor.join("examples").join(name);
			if candidate.exists() {
				return candidate;
			}
		}
	}
	bin
}

#[test]
fn nested_app_with_different_config_does_not_nest_tracer() {
	let outer = example_bin("compat-exec");
	let inner = example_bin("nested-probe");
	assert!(outer.exists(), "build examples first: missing {outer:?}");
	assert!(inner.exists(), "build examples first: missing {inner:?}");

	let out = Command::new(&outer)
		.arg(&inner)
		.arg("enter")
		.env("OLD_KERNEL_COMPAT", "1")
		.env("INNER_COMPAT", "1")
		.output()
		.expect("run outer -> inner");

	assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
	let stdout = String::from_utf8_lossy(&out.stdout);
	let stderr = String::from_utf8_lossy(&out.stderr);

	// Outer tracer enabled once; inner app must NOT enable a second tracer or warn about ptrace.
	assert_eq!(
		stderr.matches("enabled old kernel compatibility mode").count(),
		1,
		"unexpected stderr:\n{stderr}"
	);
	assert!(
		!stderr.contains("[inner]"),
		"inner app should not log anything:\n{stderr}"
	);
	assert!(
		!stderr.contains("ptrace unavailable"),
		"spurious ptrace warning:\n{stderr}"
	);

	// Inside inner app: already active, enabled() == false, OLD_KERNEL_COMPAT_ACTIVE exported with numeric PID.
	assert!(
		stdout.contains("before:active=true,enabled=false,env="),
		"unexpected stdout:\n{stdout}"
	);
	assert!(!stdout.contains("env=unset"), "OLD_KERNEL_COMPAT_ACTIVE not exported:\n{stdout}");
}

#[test]
fn nested_app_still_suppressed_even_when_env_is_cleared() {
	let outer = example_bin("compat-exec");
	let inner = example_bin("nested-probe");

	// Clear the entire environment between outer and inner, then re-force INNER_COMPAT=1.
	// TracerPid in /proc/self/status must still prevent double tracing.
	let out = Command::new(&outer)
		.args(["/usr/bin/env", "-i", "INNER_COMPAT=1"])
		.arg(&inner)
		.arg("run-traced")
		.env("OLD_KERNEL_COMPAT", "1")
		.output()
		.expect("run outer -> env -i -> inner");

	assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
	let stdout = String::from_utf8_lossy(&out.stdout);
	let stderr = String::from_utf8_lossy(&out.stderr);

	assert_eq!(
		stderr.matches("enabled old kernel compatibility mode").count(),
		1,
		"unexpected stderr:\n{stderr}"
	);
	assert!(!stderr.contains("ptrace unavailable"), "stderr:\n{stderr}");
	assert!(
		stdout.contains("before:active=true,enabled=false,env=unset;after:active=true"),
		"unexpected stdout:\n{stdout}"
	);
}

#[test]
fn stale_env_marker_without_live_tracer_does_not_disable_layer() {
	let inner = example_bin("nested-probe");

	// Simulate a leaked OLD_KERNEL_COMPAT_ACTIVE from an exited/detached parent
	// while no tracer is actually attached (TracerPid == 0).
	let out = Command::new(&inner)
		.arg("enter")
		.env("OLD_KERNEL_COMPAT_ACTIVE", "999999")
		.env("INNER_COMPAT", "1")
		.output()
		.expect("run inner with stale env");

	assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
	let stdout = String::from_utf8_lossy(&out.stdout);
	let stderr = String::from_utf8_lossy(&out.stderr);

	// Must ignore the stale env var and start its own tracer.
	assert_eq!(
		stderr.matches("[inner] enabled old kernel compatibility mode").count(),
		1,
		"expected inner tracer to start despite stale env; stderr:\n{stderr}"
	);
	assert!(
		stdout.contains("before:active=false,enabled=true,env=999999;after:active=true,env="),
		"unexpected stdout:\n{stdout}"
	);
	assert!(
		!stdout.contains("after:active=true,env=999999"),
		"env marker should be updated to the new tracer pid:\n{stdout}"
	);
}
