use std::time::Duration;

use dae_outbound::juicity;

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage124Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) server_name: String,
    pub(super) targets: Vec<String>,
    pub(super) password: Vec<u8>,
    pub(super) timeout: Duration,
}

impl Default for Stage124Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            server_name: juicity::DEFAULT_H3_SERVER_NAME.to_owned(),
            targets: juicity::DEFAULT_AUTH_LIFECYCLE_TARGETS
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
            password: juicity::DEFAULT_LIVE_EKM_AUTH_PASSWORD.as_bytes().to_vec(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl Stage124Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut custom_targets = false;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage124 --benchmark-iters")?, arg)?;
                }
                "--server-name" => {
                    opts.server_name = next_value(&mut iter, "stage124 --server-name")?;
                }
                "--target" => {
                    push_target(
                        &mut opts.targets,
                        &mut custom_targets,
                        next_value(&mut iter, "stage124 --target")?,
                    );
                }
                "--targets" => {
                    replace_targets(
                        &mut opts.targets,
                        &mut custom_targets,
                        &next_value(&mut iter, "stage124 --targets")?,
                    );
                }
                "--password" => {
                    opts.password = next_value(&mut iter, "stage124 --password")?.into_bytes();
                }
                "--timeout-ms" => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        &next_value(&mut iter, "stage124 --timeout-ms")?,
                        arg,
                    )?);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--server-name=") => {
                    opts.server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    push_target(
                        &mut opts.targets,
                        &mut custom_targets,
                        arg.split_once('=').unwrap().1.to_owned(),
                    );
                }
                _ if arg.starts_with("--targets=") => {
                    replace_targets(
                        &mut opts.targets,
                        &mut custom_targets,
                        arg.split_once('=').unwrap().1,
                    );
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    opts.timeout = Duration::from_millis(parse_u64(
                        arg.split_once('=').unwrap().1,
                        "--timeout-ms",
                    )?);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage124 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage124 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.password.is_empty() {
            return Err(RunnerOutput::usage("stage124 --password cannot be empty"));
        }
        if opts.targets.is_empty() || opts.targets.iter().any(|target| target.is_empty()) {
            return Err(RunnerOutput::usage(
                "stage124 requires at least one non-empty --target",
            ));
        }
        Ok(opts)
    }
}

fn push_target(targets: &mut Vec<String>, custom_targets: &mut bool, target: String) {
    if !*custom_targets {
        targets.clear();
        *custom_targets = true;
    }
    targets.push(target);
}

fn replace_targets(targets: &mut Vec<String>, custom_targets: &mut bool, input: &str) {
    targets.clear();
    *custom_targets = true;
    targets.extend(input.split(',').map(str::trim).map(str::to_owned));
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
