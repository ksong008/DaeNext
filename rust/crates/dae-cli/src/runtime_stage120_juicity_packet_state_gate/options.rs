use crate::runner::RunnerOutput;

pub(super) const DEFAULT_PORT_ZERO_TARGET: &str = "stage120-zero.example:0";
pub(super) const DEFAULT_STREAM_TARGET: &str = "stage120-stream.example:5353";
pub(super) const DEFAULT_PAYLOAD: &[u8] = b"stage120-juicity-packet-state";

#[derive(Debug, Clone)]
pub(super) struct Stage120Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) port_zero_target: String,
    pub(super) stream_target: String,
    pub(super) payload: Vec<u8>,
}

impl Default for Stage120Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            port_zero_target: DEFAULT_PORT_ZERO_TARGET.to_owned(),
            stream_target: DEFAULT_STREAM_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
        }
    }
}

impl Stage120Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage120 --benchmark-iters")?, arg)?;
                }
                "--port-zero-target" => {
                    opts.port_zero_target = next_value(&mut iter, "stage120 --port-zero-target")?;
                }
                "--stream-target" => {
                    opts.stream_target = next_value(&mut iter, "stage120 --stream-target")?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage120 --payload")?.into_bytes();
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--port-zero-target=") => {
                    opts.port_zero_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--stream-target=") => {
                    opts.stream_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage120 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage120 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.payload.is_empty() {
            return Err(RunnerOutput::usage("stage120 --payload cannot be empty"));
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
