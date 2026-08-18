use super::*;
pub fn parse_config(_input: &str) -> Result<Vec<Section>, ConfigError> {
    if _input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Parse(format!(
            "config exceeds byte limit of {MAX_CONFIG_BYTES}"
        )));
    }
    let tokens = Lexer::new(_input).tokenize()?;
    Parser::new(_input, tokens).parse_sections()
}
