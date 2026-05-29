use std::io::{self, BufReader, Write};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["connectivity-map", "serve"] {
        let stdin = io::stdin();
        let stdout = io::stdout();
        if let Err(err) = dae_aya_bpf_loader::run_connectivity_map_serve(
            BufReader::new(stdin.lock()),
            stdout.lock(),
        ) {
            let _ = writeln!(io::stderr(), "connectivity-map serve failed: {err}");
            std::process::exit(1);
        }
        return;
    }

    let output = dae_aya_bpf_loader::run_with_args(args);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
