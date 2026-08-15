use std::fmt;

use crate::ast::Function;
use crate::dynamic::DynamicFunctionValue;
use crate::parser::parse_config;
use crate::schema::{Config, Routing, build_config_owned};

pub const EMPTY_GROUP_SECTION: &str = "group {}";
pub const EMPTY_SUBSCRIPTION_SECTION: &str = "subscription {}";
pub const EMPTY_NODE_SECTION: &str = "node {}";
pub const EMPTY_ROUTING_SECTION: &str = "routing {}";
pub const EMPTY_DNS_SECTION: &str = "dns {}";
pub const EMPTY_GLOBAL_SECTION: &str = "global {}";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigApiError(String);

impl fmt::Display for ConfigApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigApiError {}

pub fn empty_config() -> Result<Config, ConfigApiError> {
    let sections = parse_config("global{} routing{}").map_err(config_api_error)?;
    build_config_owned(sections).map_err(config_api_error)
}

pub fn parse_config_sections(
    global_section: Option<&str>,
    dns_section: Option<&str>,
    routing_section: Option<&str>,
) -> Result<Config, ConfigApiError> {
    let sections = [
        global_section.unwrap_or(EMPTY_GLOBAL_SECTION),
        dns_section.unwrap_or(EMPTY_DNS_SECTION),
        routing_section.unwrap_or(EMPTY_ROUTING_SECTION),
        EMPTY_GROUP_SECTION,
        EMPTY_SUBSCRIPTION_SECTION,
        EMPTY_NODE_SECTION,
    ];
    let mut text =
        String::with_capacity(sections.iter().map(|section| section.len()).sum::<usize>() + 5);
    for (index, section) in sections.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        text.push_str(section);
    }
    let sections = parse_config(&text).map_err(config_api_error)?;
    build_config_owned(sections).map_err(config_api_error)
}

pub fn necessary_outbounds(routing: &Routing) -> Vec<String> {
    let mut outbounds = Vec::with_capacity(routing.rules.len() + 1);
    outbounds.push(dynamic_function_name(&routing.fallback));
    for rule in &routing.rules {
        let mut outbound = rule.outbound.name.clone();
        if outbound != "must_rules" {
            outbound = outbound
                .strip_prefix("must_")
                .unwrap_or(&outbound)
                .to_owned();
        }
        outbounds.push(outbound);
    }
    deduplicate(outbounds)
}

pub fn function_param_values(function: &Function) -> Vec<(String, String)> {
    function
        .params
        .iter()
        .map(|param| (param.key.clone(), param.val.clone()))
        .collect()
}

fn dynamic_function_name(value: &DynamicFunctionValue) -> String {
    match value {
        DynamicFunctionValue::Nil => String::new(),
        DynamicFunctionValue::String(name) => trim_must_name(name),
        DynamicFunctionValue::Function(function) => function.name.clone(),
        DynamicFunctionValue::FunctionList(functions) => functions
            .first()
            .map(|function| function.name.clone())
            .unwrap_or_default(),
    }
}

fn trim_must_name(name: &str) -> String {
    if name == "must_rules" {
        name.to_owned()
    } else {
        name.strip_prefix("must_").unwrap_or(name).to_owned()
    }
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

fn config_api_error(error: impl fmt::Display) -> ConfigApiError {
    ConfigApiError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_LOG_LEVEL, DynamicFunctionValue};

    #[test]
    fn config_api_matches_golden_fixture() {
        let fixture = dae_golden::load_json("engine/config_api/empty_parse.json").unwrap();
        let empty_fixture = &fixture["empty_config"];
        let empty = empty_config().unwrap();
        assert_eq!(empty.global.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(
            empty.global.fallback_resolver,
            empty_fixture["fallback_resolver"].as_str().unwrap()
        );
        assert_eq!(
            empty.global.udp_endpoint_pool_size,
            empty_fixture["udp_endpoint_pool_size"].as_i64().unwrap() as i32
        );

        let parse_fixture = &fixture["parse_config"];
        let parsed = parse_config_sections(
            Some(parse_fixture["global_input"].as_str().unwrap()),
            None,
            Some(parse_fixture["routing_input"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            parsed.global.log_level,
            parse_fixture["log_level"].as_str().unwrap()
        );
        assert_eq!(
            necessary_outbounds(&parsed.routing),
            parse_fixture["necessary_outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
        match &parsed.routing.fallback {
            DynamicFunctionValue::Function(function) => {
                assert_eq!(
                    function.name,
                    parse_fixture["fallback"]["name"].as_str().unwrap()
                );
                assert_eq!(function.params[0].val, "must");
            }
            other => panic!("fallback should be a function, got {other:?}"),
        }
    }
}
