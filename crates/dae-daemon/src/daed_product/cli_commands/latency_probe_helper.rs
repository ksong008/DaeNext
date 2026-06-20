use super::*;

pub(crate) fn run_latency_probe_helper_command(args: &[String]) -> DaedProductOutput {
    if args != ["--stdin-json"] {
        return DaedProductOutput::usage("latency-probe-helper requires --stdin-json");
    }
    let mut input = Vec::new();
    let mut stdin = io::stdin().take((LATENCY_PROBE_HELPER_MAX_IO_BYTES as u64) + 1);
    if let Err(err) = stdin.read_to_end(&mut input) {
        return DaedProductOutput::error(format!("read latency probe helper stdin: {err}"));
    }
    match latency_probe_helper_response_from_request(&input) {
        Ok(response) => DaedProductOutput::ok(format!("{response}\n")),
        Err(err) => DaedProductOutput::error(format!("latency probe helper failed: {err}")),
    }
}
