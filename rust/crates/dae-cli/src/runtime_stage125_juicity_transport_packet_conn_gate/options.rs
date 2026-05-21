use std::time::Duration;

use dae_outbound::juicity;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage125Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) target: String,
    pub(super) payload: Vec<u8>,
    pub(super) response_payload: Vec<u8>,
    pub(super) timeout: Duration,
}

impl Default for Stage125Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            target: juicity::DEFAULT_TRANSPORT_PACKET_CONN_TARGET.to_owned(),
            payload: juicity::DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD.to_vec(),
            response_payload: juicity::DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE.to_vec(),
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage125Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage125 --benchmark-iters")?, arg)?;
                }
                "--target" => {
                    opts.target = next_value(&mut iter, "stage125 --target")?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage125 --payload")?.into_bytes();
                }
                "--response-payload" => {
                    opts.response_payload =
                        next_value(&mut iter, "stage125 --response-payload")?.into_bytes();
                }
                "--timeout-ms" => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage125 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--response-payload=") => {
                    opts.response_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage125 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage125 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.payload.is_empty() {
            return Err(RunnerOutput::usage("stage125 --payload cannot be empty"));
        }
        if opts.response_payload.is_empty() {
            return Err(RunnerOutput::usage(
                "stage125 --response-payload cannot be empty",
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
