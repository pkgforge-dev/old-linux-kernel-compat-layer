#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]

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

	assert!(
		stdout.contains("before:active=true,enabled=false,env=1;after:active=true,env=1"),
		"unexpected stdout:\n{stdout}"
	);
}

#[test]
fn env_active_suppresses_tracer_without_reading_proc() {
	let inner = example_bin("nested-probe");

	let out = Command::new(&inner)
		.arg("run-traced")
		.env("OLD_KERNEL_COMPAT_ACTIVE", "1")
		.env("INNER_COMPAT", "1")
		.output()
		.expect("run inner with OLD_KERNEL_COMPAT_ACTIVE=1");

	assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
	let stdout = String::from_utf8_lossy(&out.stdout);
	let stderr = String::from_utf8_lossy(&out.stderr);

	assert!(
		!stderr.contains("enabled old kernel compatibility mode"),
		"should not start tracer when OLD_KERNEL_COMPAT_ACTIVE=1; stderr:\n{stderr}"
	);
	assert!(
		stdout.contains("before:active=true,enabled=false,env=1;after:active=true"),
		"unexpected stdout:\n{stdout}"
	);
}

#[test]
fn standalone_app_sets_env_active_when_entering() {
	let inner = example_bin("nested-probe");

	let out = Command::new(&inner)
		.arg("enter")
		.env_remove("OLD_KERNEL_COMPAT_ACTIVE")
		.env("INNER_COMPAT", "1")
		.output()
		.expect("run standalone inner");

	assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
	let stdout = String::from_utf8_lossy(&out.stdout);
	let stderr = String::from_utf8_lossy(&out.stderr);

	assert_eq!(
		stderr.matches("[inner] enabled old kernel compatibility mode").count(),
		1,
		"expected inner tracer to start; stderr:\n{stderr}"
	);
	assert!(
		stdout.contains("before:active=false,enabled=true,env=unset;after:active=true,env=1"),
		"unexpected stdout:\n{stdout}"
	);
}
