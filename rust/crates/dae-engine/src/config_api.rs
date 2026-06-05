use dae_config::ast::Function;
use dae_config::dynamic::DynamicFunctionValue;
use dae_config::parser::parse_config;
use dae_config::schema::{Config, Routing, build_config_owned};

use crate::EngineError;

pub const EMPTY_GROUP_SECTION: &str = "group {}";
pub const EMPTY_SUBSCRIPTION_SECTION: &str = "subscription {}";
pub const EMPTY_NODE_SECTION: &str = "node {}";
pub const EMPTY_ROUTING_SECTION: &str = "routing {}";
pub const EMPTY_DNS_SECTION: &str = "dns {}";
pub const EMPTY_GLOBAL_SECTION: &str = "global {}";

pub fn empty_config() -> Result<Config, EngineError> {
    let sections =
        parse_config("global{} routing{}").map_err(|err| EngineError::Parse(err.to_string()))?;
    build_config_owned(sections).map_err(|err| EngineError::Parse(err.to_string()))
}

pub fn parse_config_sections(
    global_section: Option<&str>,
    dns_section: Option<&str>,
    routing_section: Option<&str>,
) -> Result<Config, EngineError> {
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
    let sections = parse_config(&text).map_err(|err| EngineError::Parse(err.to_string()))?;
    build_config_owned(sections).map_err(|err| EngineError::Parse(err.to_string()))
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

pub fn function_param_values(function: &Function) -> Vec<(String, String)> {
    function
        .params
        .iter()
        .map(|param| (param.key.clone(), param.val.clone()))
        .collect()
}
