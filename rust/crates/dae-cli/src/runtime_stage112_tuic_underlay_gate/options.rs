use std::time::Duration;

use crate::runner::RunnerOutput;

pub(super) const DEFAULT_PAYLOAD: &[u8] = b"stage112-tuic-udp-underlay-ping";
pub(super) const DEFAULT_MARK: u32 = 1234;

#[derive(Debug, Clone)]
pub(super) struct Stage112Options {
    pub(super) execute_smoke: bool,
    pub(super) ack_root_gate: bool,
    pub(super) benchmark_iters: usize,
    pub(super) payload: Vec<u8>,
    pub(super) so_mark: u32,
    pub(super) mptcp: bool,
    pub(super) timeout: Duration,
}

impl Default for Stage112Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: DEFAULT_MARK,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage112Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage112 --benchmark-iters")?, arg)?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage112 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage112 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage112 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage112 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage112 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.payload.is_empty() {
            return Err(RunnerOutput::usage("stage112 --payload cannot be empty"));
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

fn parse_u32(input: &str, context: &str) -> Result<u32, RunnerOutput> {
    input
        .parse::<u32>()
        .map_err(|_| RunnerOutput::usage(format!("invalid u32 for {context}: {input}")))
}

fn parse_u64(input: &str, context: &str) -> Result<u64, RunnerOutput> {
    input
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid u64 for {context}: {input}")))
}
