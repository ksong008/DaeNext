use std::io::{self, Write};

#[path = "../binary_allocator.rs"]
mod allocator;

fn main() {
    let version = dae_daemon::version_from_env();
    let output = dae_daemon::run_with_args_and_version(std::env::args().skip(1), &version);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
