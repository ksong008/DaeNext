use std::io::{self, BufReader, Read, Write};

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
    if args == ["connectivity-map", "serve-binary"] {
        let stdin = io::stdin();
        let stdout = io::stdout();
        if let Err(err) =
            dae_aya_bpf_loader::run_connectivity_map_serve_binary(stdin.lock(), stdout.lock())
        {
            let _ = writeln!(io::stderr(), "connectivity-map serve-binary failed: {err}");
            std::process::exit(1);
        }
        return;
    }
    if args == ["domain-routing-map", "serve"] {
        let stdin = io::stdin();
        let stdout = io::stdout();
        if let Err(err) = dae_aya_bpf_loader::run_domain_routing_map_serve(
            BufReader::new(stdin.lock()),
            stdout.lock(),
        ) {
            let _ = writeln!(io::stderr(), "domain-routing-map serve failed: {err}");
            std::process::exit(1);
        }
        return;
    }
    if args == ["routing-map", "apply"] {
        run_json_stdin_command(dae_aya_bpf_loader::run_routing_map_apply_json);
        return;
    }
    if args == ["domain-routing-map", "apply"] {
        run_json_stdin_command(dae_aya_bpf_loader::run_domain_routing_map_apply_json);
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

fn run_json_stdin_command(handler: fn(&str) -> dae_aya_bpf_loader::LoaderOutput) {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        let _ = writeln!(io::stderr(), "read stdin failed: {err}");
        std::process::exit(1);
    }
    let output = handler(&input);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = io::stderr().write_all(output.stderr.as_bytes());
    }
    std::process::exit(output.exit_code);
}
