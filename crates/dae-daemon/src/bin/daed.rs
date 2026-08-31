use std::io::{self, Write};

#[path = "../binary_allocator.rs"]
mod allocator;

fn main() {
    let command = std::env::args_os().nth(1);
    if dae_daemon::allocator_bootstrap_required_for_command(command.as_deref())
        && let Err(err) = dae_daemon::ensure_allocator_startup_configuration()
    {
        let _ = writeln!(
            io::stderr(),
            "daed: failed to apply allocator startup configuration: {err}"
        );
        std::process::exit(1);
    }
    let version = dae_daemon::version_from_env();
    let output =
        dae_daemon::run_daed_product_with_args_and_version(std::env::args().skip(1), &version);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
