use std::time::Duration;

use dae_outbound::{hysteria2, juicity, tuic};

use crate::runner::RunnerOutput;

#[derive(Debug, Clone)]
pub(super) struct Stage132Options {
    pub(super) execute_smoke: bool,
    pub(super) hysteria2: hysteria2::Hysteria2TrueQuicDataplaneOptions,
    pub(super) tuic: tuic::TuicTrueQuicDataplaneOptions,
    pub(super) juicity: juicity::JuicityOutboundDataplaneOptions,
}

impl Default for Stage132Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            hysteria2: hysteria2::Hysteria2TrueQuicDataplaneOptions::default(),
            tuic: tuic::TuicTrueQuicDataplaneOptions::default(),
            juicity: juicity::JuicityOutboundDataplaneOptions::default(),
        }
    }
}

impl Stage132Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage132 --timeout-ms")?, arg)?;
                    opts.set_timeout_ms(timeout_ms);
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.set_timeout_ms(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage132 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }

    fn set_timeout_ms(&mut self, timeout_ms: u64) {
        let timeout = Duration::from_millis(timeout_ms);
        self.hysteria2.quic.timeout = timeout;
        self.tuic.quic.timeout = timeout;
        self.juicity.client_integration.timeout = timeout;
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

fn parse_u64(input: &str, context: &str) -> Result<u64, RunnerOutput> {
    input
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid u64 for {context}: {input}")))
}
