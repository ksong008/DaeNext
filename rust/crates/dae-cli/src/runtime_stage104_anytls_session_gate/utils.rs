use super::*;

pub(super) fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    context: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {context}")))
}

pub(super) fn parse_usize(value: &str, context: &str) -> Result<usize, RunnerOutput> {
    value
        .parse::<usize>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}

pub(super) fn parse_u32(value: &str, context: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}

pub(super) fn parse_u64(value: &str, context: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
