use super::*;

pub(super) fn patch_fallback_resolver(config: &Config) -> Result<(), ConfigError> {
    SocketAddr::from_str(&config.global.fallback_resolver)
        .map(|_| ())
        .map_err(|_| {
            ConfigError::Build(format!(
                "invalid global.fallback_resolver {:?}: not an ip:port",
                config.global.fallback_resolver
            ))
        })
}

pub(super) fn patch_tcp_check_http_method(config: &mut Config) {
    if !is_valid_http_method(&config.global.tcp_check_http_method) {
        config.global.tcp_check_http_method = "CONNECT".to_owned();
    }
}

pub(super) fn patch_empty_dns(config: &mut Config) {
    if matches!(
        config.dns.routing.request.fallback,
        DynamicFunctionValue::Nil
    ) {
        config.dns.routing.request.fallback = DynamicFunctionValue::String("asis".to_owned());
    }
    if matches!(
        config.dns.routing.response.fallback,
        DynamicFunctionValue::Nil
    ) {
        config.dns.routing.response.fallback = DynamicFunctionValue::String("accept".to_owned());
    }
}

pub(super) fn patch_must_outbound(config: &mut Config) -> Result<(), ConfigError> {
    for rule in &mut config.routing.rules {
        if rule.outbound.name.starts_with("must_") {
            if rule.outbound.name == "must_rules" {
                continue;
            }
            rule.outbound.name = rule.outbound.name.trim_start_matches("must_").to_owned();
            rule.outbound.params.push(Param {
                key: String::new(),
                val: "must".to_owned(),
                and_functions: Vec::new(),
                annotation: Vec::new(),
            });
        }
    }

    let mut fallback = dynamic_to_single_function(&config.routing.fallback)
        .map_err(|err| ConfigError::Build(format!("invalid routing fallback: {err}")))?;
    if fallback.name.starts_with("must_") {
        fallback.name = fallback.name.trim_start_matches("must_").to_owned();
        fallback.params.push(Param {
            key: String::new(),
            val: "must".to_owned(),
            and_functions: Vec::new(),
            annotation: Vec::new(),
        });
        config.routing.fallback = DynamicFunctionValue::Function(fallback);
    }
    Ok(())
}

fn dynamic_to_single_function(value: &DynamicFunctionValue) -> Result<Function, String> {
    match value {
        DynamicFunctionValue::String(name) => Ok(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        }),
        DynamicFunctionValue::Function(function) => Ok(function.clone()),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(functions[0].clone())
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "expected exactly 1 fallback function, got {}",
            functions.len()
        )),
        DynamicFunctionValue::Nil => Err("unsupported fallback type nil".to_owned()),
    }
}
