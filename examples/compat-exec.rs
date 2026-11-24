use old_linux_kernel_compat_layer as kernel_compat;

fn main() {
	kernel_compat::exit_if_internal_probe();
	let args: Vec<String> = std::env::args().skip(1).collect();
	if args.is_empty() {
		eprintln!("Usage: compat-exec CMD [ARGS...]");
		std::process::exit(1);
	}
	kernel_compat::run_command_traced(&args);
}
