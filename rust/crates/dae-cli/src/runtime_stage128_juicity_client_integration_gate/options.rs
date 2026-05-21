use std::time::Duration;

use dae_outbound::juicity;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage128Options {
    pub(super) execute_smoke: bool,
    pub(super) auth_targets: Vec<String>,
    pub(super) auth_iterations: usize,
    pub(super) transport_iterations: usize,
    pub(super) stream_iterations: usize,
    pub(super) congestion_iterations: usize,
    pub(super) max_in_flight_streams: usize,
    pub(super) congestion_control: String,
    pub(super) server_name: String,
    pub(super) timeout: Duration,
}

impl Default for Stage128Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            auth_targets: juicity::DEFAULT_AUTH_LIFECYCLE_TARGETS
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
            auth_iterations: juicity::DEFAULT_CLIENT_INTEGRATION_AUTH_ITERATIONS,
            transport_iterations: juicity::DEFAULT_CLIENT_INTEGRATION_TRANSPORT_ITERATIONS,
            stream_iterations: juicity::DEFAULT_CLIENT_INTEGRATION_STREAM_ITERATIONS,
            congestion_iterations: juicity::DEFAULT_CLIENT_INTEGRATION_CONGESTION_ITERATIONS,
            max_in_flight_streams: juicity::DEFAULT_CLIENT_INTEGRATION_MAX_IN_FLIGHT,
            congestion_control: juicity::DEFAULT_STREAM_PACKET_CONGESTION_CONTROL.to_owned(),
            server_name: juicity::DEFAULT_H3_SERVER_NAME.to_owned(),
            timeout: Duration::from_secs(12),
        }
    }
}

impl Stage128Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--auth-iters" => {
                    opts.auth_iterations =
                        parse_usize(&next_value(&mut iter, "stage128 --auth-iters")?, arg)?;
                }
                "--transport-iters" => {
                    opts.transport_iterations =
                        parse_usize(&next_value(&mut iter, "stage128 --transport-iters")?, arg)?;
                }
                "--stream-iters" => {
                    opts.stream_iterations =
                        parse_usize(&next_value(&mut iter, "stage128 --stream-iters")?, arg)?;
                }
                "--congestion-iters" => {
                    opts.congestion_iterations =
                        parse_usize(&next_value(&mut iter, "stage128 --congestion-iters")?, arg)?;
                }
                "--max-in-flight-streams" => {
                    opts.max_in_flight_streams = parse_usize(
                        &next_value(&mut iter, "stage128 --max-in-flight-streams")?,
                        arg,
                    )?;
                }
                "--congestion-control" => {
                    opts.congestion_control =
                        next_value(&mut iter, "stage128 --congestion-control")?;
                }
                "--server-name" => {
                    opts.server_name = next_value(&mut iter, "stage128 --server-name")?;
                }
                "--timeout-ms" => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage128 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--auth-iters=") => {
                    opts.auth_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--auth-iters")?;
                }
                _ if arg.starts_with("--transport-iters=") => {
                    opts.transport_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--transport-iters")?;
                }
                _ if arg.starts_with("--stream-iters=") => {
                    opts.stream_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--stream-iters")?;
                }
                _ if arg.starts_with("--congestion-iters=") => {
                    opts.congestion_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--congestion-iters")?;
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
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage128 argument: {arg}"
                    )));
                }
            }
        }
        if opts.auth_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage128 --auth-iters must be greater than zero",
            ));
        }
        if opts.transport_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage128 --transport-iters must be greater than zero",
            ));
        }
        if opts.stream_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage128 --stream-iters must be greater than zero",
            ));
        }
        if opts.congestion_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage128 --congestion-iters must be greater than zero",
            ));
        }
        if opts.max_in_flight_streams == 0 {
            return Err(RunnerOutput::usage(
                "stage128 --max-in-flight-streams must be greater than zero",
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
