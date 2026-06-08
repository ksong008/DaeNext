use super::*;
pub fn parse_config(_input: &str) -> Result<Vec<Section>, ConfigError> {
    let tokens = Lexer::new(_input).tokenize()?;
    Parser::new(_input, tokens).parse_sections()
}
