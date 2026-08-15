use super::*;
pub(crate) fn parse_config(input: &str) -> Config {
    let sections = dae_config::parser::parse_config(input).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}
