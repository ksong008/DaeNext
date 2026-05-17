use std::io::{self, Write};

fn main() {
    let output = dae_cli::run_with_args(std::env::args().skip(1));
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
