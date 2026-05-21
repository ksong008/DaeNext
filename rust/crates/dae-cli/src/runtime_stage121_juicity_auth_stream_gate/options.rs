use crate::runner::RunnerOutput;

pub(super) const DEFAULT_TARGET: &str = "stage121-zero.example:0";

#[derive(Debug, Clone)]
pub(super) struct Stage121Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) target: String,
}

impl Default for Stage121Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            target: DEFAULT_TARGET.to_owned(),
        }
    }
}

impl Stage121Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage121 --benchmark-iters")?, arg)?;
                }
                "--target" => {
                    opts.target = next_value(&mut iter, "stage121 --target")?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage121 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage121 --benchmark-iters must be greater than zero",
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
