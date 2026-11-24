use old_linux_kernel_compat_layer::{self as kernel_compat, Config};

fn main() {
	let _ = kernel_compat::init(Config {
		env_enable: "INNER_COMPAT",
		env_enable_fallback: Some("OLD_KERNEL_COMPAT"),
		log_prefix: "[inner]",
		..Config::default()
	});
	kernel_compat::exit_if_internal_probe();

	let mode = std::env::args().nth(1).unwrap_or_else(|| "enter".to_string());
	let active_before = kernel_compat::is_active();
	let enabled_before = kernel_compat::enabled();
	let active_env = std::env::var(kernel_compat::ENV_ACTIVE).unwrap_or_else(|_| "unset".into());

	match mode.as_str() {
		"enter" => {
			kernel_compat::enter();
			let active_after = kernel_compat::is_active();
			let active_env_after =
				std::env::var(kernel_compat::ENV_ACTIVE).unwrap_or_else(|_| "unset".into());
			println!(
				"before:active={active_before},enabled={enabled_before},env={active_env};after:active={active_after},env={active_env_after}"
			);
		}
		"run-traced" => {
			kernel_compat::run_traced(&|| {
				let active_after = kernel_compat::is_active();
				println!(
					"before:active={active_before},enabled={enabled_before},env={active_env};after:active={active_after}"
				);
				std::process::exit(0);
			});
		}
		_ => {
			eprintln!("unknown mode: {mode}");
			std::process::exit(2);
		}
	}
}
