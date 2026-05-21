use std::time::Duration;

use dae_outbound::hysteria2;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage130Options {
    pub(super) execute_smoke: bool,
    pub(super) dataplane: hysteria2::Hysteria2TrueQuicDataplaneOptions,
}

impl Default for Stage130Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            dataplane: hysteria2::Hysteria2TrueQuicDataplaneOptions::default(),
        }
    }
}

impl Stage130Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--stream-iters" => {
                    opts.dataplane.quic.stream_iterations =
                        parse_usize(&next_value(&mut iter, "stage130 --stream-iters")?, arg)?;
                }
                "--datagram-iters" => {
                    opts.dataplane.quic.datagram_iterations =
                        parse_usize(&next_value(&mut iter, "stage130 --datagram-iters")?, arg)?;
                }
                "--timeout-ms" => {
                    opts.dataplane.quic.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage130 --timeout-ms")?,
                        arg,
                    )?);
                }
                "--udp-hop-interval-ms" => {
                    opts.dataplane.udp_hop_interval_ms = parse_u64(
                        &next_value(&mut iter, "stage130 --udp-hop-interval-ms")?,
                        arg,
                    )?;
                }
                "--port-hop-iters" => {
                    opts.dataplane.port_hop_iterations =
                        parse_usize(&next_value(&mut iter, "stage130 --port-hop-iters")?, arg)?;
                }
                _ if arg.starts_with("--stream-iters=") => {
                    opts.dataplane.quic.stream_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--stream-iters")?;
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
                _ if arg.starts_with("--udp-hop-interval-ms=") => {
                    opts.dataplane.udp_hop_interval_ms =
                        parse_u64(arg.split_once('=').unwrap().1, "--udp-hop-interval-ms")?;
                }
                _ if arg.starts_with("--port-hop-iters=") => {
                    opts.dataplane.port_hop_iterations =
                        parse_usize(arg.split_once('=').unwrap().1, "--port-hop-iters")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage130 argument: {arg}"
                    )));
                }
            }
        }
        if opts.dataplane.quic.stream_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage130 --stream-iters must be greater than zero",
            ));
        }
        if opts.dataplane.quic.datagram_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage130 --datagram-iters must be greater than zero",
            ));
        }
        if opts.dataplane.udp_hop_interval_ms == 0 {
            return Err(RunnerOutput::usage(
                "stage130 --udp-hop-interval-ms must be greater than zero",
            ));
        }
        if opts.dataplane.port_hop_iterations == 0 {
            return Err(RunnerOutput::usage(
                "stage130 --port-hop-iters must be greater than zero",
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
