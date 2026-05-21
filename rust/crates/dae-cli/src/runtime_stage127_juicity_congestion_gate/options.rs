use std::time::Duration;

use dae_outbound::juicity;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage127Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) max_in_flight_streams: usize,
    pub(super) congestion_control: String,
    pub(super) server_name: String,
    pub(super) target: String,
    pub(super) response_target: String,
    pub(super) payload: Vec<u8>,
    pub(super) response_payload: Vec<u8>,
    pub(super) timeout: Duration,
}

impl Default for Stage127Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: juicity::DEFAULT_STREAM_PACKET_CONGESTION_ITERATIONS,
            max_in_flight_streams: juicity::DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT,
            congestion_control: juicity::DEFAULT_STREAM_PACKET_CONGESTION_CONTROL.to_owned(),
            server_name: juicity::DEFAULT_H3_SERVER_NAME.to_owned(),
            target: juicity::DEFAULT_STREAM_PACKET_CONGESTION_TARGET.to_owned(),
            response_target: juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_TARGET.to_owned(),
            payload: juicity::default_congestion_payload(
                juicity::DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN,
            ),
            response_payload: juicity::default_congestion_payload(
                juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN,
            ),
            timeout: Duration::from_secs(10),
        }
    }
}

impl Stage127Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage127 --benchmark-iters")?, arg)?;
                }
                "--max-in-flight-streams" => {
                    opts.max_in_flight_streams = parse_usize(
                        &next_value(&mut iter, "stage127 --max-in-flight-streams")?,
                        arg,
                    )?;
                }
                "--congestion-control" => {
                    opts.congestion_control =
                        next_value(&mut iter, "stage127 --congestion-control")?;
                }
                "--server-name" => {
                    opts.server_name = next_value(&mut iter, "stage127 --server-name")?;
                }
                "--target" => {
                    opts.target = next_value(&mut iter, "stage127 --target")?;
                }
                "--response-target" => {
                    opts.response_target = next_value(&mut iter, "stage127 --response-target")?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage127 --payload")?.into_bytes();
                }
                "--response-payload" => {
                    opts.response_payload =
                        next_value(&mut iter, "stage127 --response-payload")?.into_bytes();
                }
                "--payload-len" => {
                    opts.payload = juicity::default_congestion_payload(parse_usize(
                        &next_value(&mut iter, "stage127 --payload-len")?,
                        arg,
                    )?);
                }
                "--response-payload-len" => {
                    opts.response_payload = juicity::default_congestion_payload(parse_usize(
                        &next_value(&mut iter, "stage127 --response-payload-len")?,
                        arg,
                    )?);
                }
                "--timeout-ms" => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage127 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--max-in-flight-streams=") => {
                    opts.max_in_flight_streams =
                        parse_usize(arg.split_once('=').unwrap().1, "--max-in-flight-streams")?;
                }
                _ if arg.starts_with("--congestion-control=") => {
                    opts.congestion_control = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--server-name=") => {
                    opts.server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--response-target=") => {
                    opts.response_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--response-payload=") => {
                    opts.response_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--payload-len=") => {
                    opts.payload = juicity::default_congestion_payload(parse_usize(
                        arg.split_once('=').unwrap().1,
                        "--payload-len",
                    )?);
                }
                _ if arg.starts_with("--response-payload-len=") => {
                    opts.response_payload = juicity::default_congestion_payload(parse_usize(
                        arg.split_once('=').unwrap().1,
                        "--response-payload-len",
                    )?);
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage127 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage127 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.max_in_flight_streams == 0 {
            return Err(RunnerOutput::usage(
                "stage127 --max-in-flight-streams must be greater than zero",
            ));
        }
        if opts.payload.is_empty() {
            return Err(RunnerOutput::usage("stage127 --payload cannot be empty"));
        }
        if opts.response_payload.is_empty() {
            return Err(RunnerOutput::usage(
                "stage127 --response-payload cannot be empty",
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
