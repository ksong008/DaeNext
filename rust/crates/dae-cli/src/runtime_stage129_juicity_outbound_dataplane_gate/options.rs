use std::time::Duration;

use dae_outbound::juicity;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage129Options {
    pub(super) execute_smoke: bool,
    pub(super) outbound: juicity::JuicityOutboundDataplaneOptions,
}

impl Default for Stage129Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            outbound: juicity::JuicityOutboundDataplaneOptions::default(),
        }
    }
}

impl Stage129Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--auth-iters" => {
                    opts.outbound.client_integration.auth_iterations =
                        parse_usize(&next_value(&mut iter, "stage129 --auth-iters")?, arg)?;
                }
                "--transport-iters" => {
                    opts.outbound.client_integration.transport_iterations =
                        parse_usize(&next_value(&mut iter, "stage129 --transport-iters")?, arg)?;
                }
                "--stream-iters" => {
                    opts.outbound.client_integration.stream_iterations =
                        parse_usize(&next_value(&mut iter, "stage129 --stream-iters")?, arg)?;
                }
                "--congestion-iters" => {
                    opts.outbound.client_integration.congestion_iterations =
                        parse_usize(&next_value(&mut iter, "stage129 --congestion-iters")?, arg)?;
                }
                "--max-in-flight-streams" => {
                    opts.outbound.client_integration.max_in_flight_streams = parse_usize(
                        &next_value(&mut iter, "stage129 --max-in-flight-streams")?,
                        arg,
                    )?;
                }
                "--congestion-control" => {
                    opts.outbound.client_integration.congestion_control =
                        next_value(&mut iter, "stage129 --congestion-control")?;
                }
                "--server-name" => {
                    opts.outbound.client_integration.server_name =
                        next_value(&mut iter, "stage129 --server-name")?;
                }
                "--timeout-ms" => {
                    opts.outbound.client_integration.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage129 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--auth-iters=") => {
                    opts.outbound.client_integration.auth_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--auth-iters")?;
                }
                _ if arg.starts_with("--transport-iters=") => {
                    opts.outbound.client_integration.transport_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--transport-iters")?;
                }
                _ if arg.starts_with("--stream-iters=") => {
                    opts.outbound.client_integration.stream_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--stream-iters")?;
                }
                _ if arg.starts_with("--congestion-iters=") => {
                    opts.outbound.client_integration.congestion_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--congestion-iters")?;
                }
                _ if arg.starts_with("--max-in-flight-streams=") => {
                    opts.outbound.client_integration.max_in_flight_streams =
                        parse_usize(arg.split_once('=').unwrap().1, "--max-in-flight-streams")?;
                }
                _ if arg.starts_with("--congestion-control=") => {
                    opts.outbound.client_integration.congestion_control =
                        arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--server-name=") => {
                    opts.outbound.client_integration.server_name =
                        arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.outbound.client_integration.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage129 argument: {arg}"
                    )));
                }
            }
        }
        if opts.outbound.client_integration.auth_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage129 --auth-iters must be greater than zero",
            ));
        }
        if opts.outbound.client_integration.transport_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage129 --transport-iters must be greater than zero",
            ));
        }
        if opts.outbound.client_integration.stream_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage129 --stream-iters must be greater than zero",
            ));
        }
        if opts.outbound.client_integration.congestion_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage129 --congestion-iters must be greater than zero",
            ));
        }
        if opts.outbound.client_integration.max_in_flight_streams == 0 {
            return Err(RunnerOutput::usage(
                "stage129 --max-in-flight-streams must be greater than zero",
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
