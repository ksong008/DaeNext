use super::*;
pub(crate) fn parse_benchmark_arg<'a>(
    arg: &str,
    iter: &mut std::slice::Iter<'a, String>,
    state: &mut DefaultOptinParsedArgs,
) -> Result<bool, DaemonOutput> {
    macro_rules! usage {
        ($($arg:tt)*) => {
            return Err(DaemonOutput::usage($($arg)*))
        };
    }
    match arg {
        "--dataplane-benchmark-iters" => {
            let Some(value) = iter.next() else {
                usage!("missing run --dataplane-benchmark-iters value");
            };
            state.dataplane_benchmark_iters = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --dataplane-benchmark-iters value",);
                }
            };
        }
        _ if arg.starts_with("--dataplane-benchmark-iters=") => {
            state.dataplane_benchmark_iters = match arg.split_once('=').unwrap().1.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --dataplane-benchmark-iters value",);
                }
            };
        }
        "--execute-matched-default-benchmark" => state.matched_default_benchmark = true,
        "--matched-benchmark-iterations" => {
            let Some(value) = iter.next() else {
                usage!("missing run --matched-benchmark-iterations value");
            };
            state.matched_benchmark_iterations = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --matched-benchmark-iterations value",);
                }
            };
        }
        _ if arg.starts_with("--matched-benchmark-iterations=") => {
            state.matched_benchmark_iterations = match arg.split_once('=').unwrap().1.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --matched-benchmark-iterations value",);
                }
            };
        }
        "--matched-ready-timeout-ms" => {
            let Some(value) = iter.next() else {
                usage!("missing run --matched-ready-timeout-ms value");
            };
            state.matched_ready_timeout_ms = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --matched-ready-timeout-ms value");
                }
            };
        }
        _ if arg.starts_with("--matched-ready-timeout-ms=") => {
            state.matched_ready_timeout_ms = match arg.split_once('=').unwrap().1.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --matched-ready-timeout-ms value");
                }
            };
        }
        "--go-tool" => {
            let Some(value) = iter.next() else {
                usage!("missing run --go-tool value");
            };
            state.go_tool = Some(value.into());
        }
        _ if arg.starts_with("--go-tool=") => {
            state.go_tool = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--go-work" => {
            let Some(value) = iter.next() else {
                usage!("missing run --go-work value");
            };
            state.go_work = Some(value.into());
        }
        _ if arg.starts_with("--go-work=") => {
            state.go_work = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--go-binary" => {
            let Some(value) = iter.next() else {
                usage!("missing run --go-binary value");
            };
            state.go_binary = Some(value.into());
        }
        _ if arg.starts_with("--go-binary=") => {
            state.go_binary = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--rust-binary" => {
            let Some(value) = iter.next() else {
                usage!("missing run --rust-binary value");
            };
            state.rust_binary = Some(value.into());
        }
        _ if arg.starts_with("--rust-binary=") => {
            state.rust_binary = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--source-dir" => {
            let Some(value) = iter.next() else {
                usage!("missing run --source-dir value");
            };
            state.source_dir = Some(value.into());
        }
        _ if arg.starts_with("--source-dir=") => {
            state.source_dir = arg.split_once('=').map(|(_, value)| value.into());
        }
        _ => return Ok(false),
    }
    Ok(true)
}
