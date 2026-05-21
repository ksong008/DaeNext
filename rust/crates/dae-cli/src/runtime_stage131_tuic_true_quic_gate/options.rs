use std::time::Duration;

use dae_outbound::tuic;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage131Options {
    pub(super) execute_smoke: bool,
    pub(super) dataplane: tuic::TuicTrueQuicDataplaneOptions,
}

impl Default for Stage131Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            dataplane: tuic::TuicTrueQuicDataplaneOptions::default(),
        }
    }
}

impl Stage131Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--datagram-iters" => {
                    opts.dataplane.quic.datagram_iterations =
                        parse_usize(&next_value(&mut iter, "stage131 --datagram-iters")?, arg)?;
                }
                "--timeout-ms" => {
                    opts.dataplane.quic.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage131 --timeout-ms")?,
                        arg,
                    )?);
                }
                "--underlay-mark" => {
                    opts.dataplane.underlay_mark =
                        parse_u32(&next_value(&mut iter, "stage131 --underlay-mark")?, arg)?;
                }
                _ if arg.starts_with("--datagram-iters=") => {
                    opts.dataplane.quic.datagram_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--datagram-iters")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.dataplane.quic.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ if arg.starts_with("--underlay-mark=") => {
                    opts.dataplane.underlay_mark =
                        parse_u32(arg.split_once('=').unwrap().1, "--underlay-mark")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage131 argument: {arg}"
                    )));
                }
            }
        }
        if opts.dataplane.quic.datagram_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage131 --datagram-iters must be greater than zero",
            ));
        }
        Ok(opts)
    }
}

fn next_value(
    iter: &mut std::slice::Iter<'_, String>,
    context: &'static str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {context}")))
}

fn parse_usize(input: &str, context: &str) -> Result<usize, RunnerOutput> {
    input
        .parse::<usize>()
        .map_err(|_| RunnerOutput::usage(format!("invalid usize for {context}: {input}")))
}

fn parse_u64(input: &str, context: &str) -> Result<u64, RunnerOutput> {
    input
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid u64 for {context}: {input}")))
}

fn parse_u32(input: &str, context: &str) -> Result<u32, RunnerOutput> {
    input
        .parse::<u32>()
        .map_err(|_| RunnerOutput::usage(format!("invalid u32 for {context}: {input}")))
}
