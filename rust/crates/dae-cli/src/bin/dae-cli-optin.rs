use std::io::{self, Write};

fn main() {
    let version = std::env::var("DAE_CLI_VERSION").unwrap_or_else(|_| "unknown".to_owned());
    let output = dae_cli::run_with_args_and_version(std::env::args().skip(1), &version);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
