use super::*;
pub(super) fn parse_error(input: &str, offset: usize, message: &str) -> ConfigError {
    let safe_offset = offset.min(input.len());
    let line_start = input[..safe_offset]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = input[safe_offset..]
        .find('\n')
        .map(|index| safe_offset + index)
        .unwrap_or(input.len());
    let line = input[..safe_offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = input[line_start..safe_offset].chars().count();
    let text = &input[line_start..line_end];
    let caret_padding = " ".repeat(column);

    ConfigError::Parse(format!(
        "line {line}:{column} {text}\n{caret_padding}^: {message}"
    ))
}
