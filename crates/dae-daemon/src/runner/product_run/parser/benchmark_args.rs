use super::*;
pub(crate) fn parse_benchmark_arg<'a>(
    arg: &str,
    iter: &mut std::slice::Iter<'a, String>,
    state: &mut ProductRunParsedArgs,
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
        _ => return Ok(false),
    }
    Ok(true)
}
