use super::parser::*;
use super::patch::*;
use super::*;

pub fn build_config(sections: &[Section]) -> Result<Config, ConfigError> {
    build_config_inputs::<BorrowedMode>(sections.iter().map(borrowed))
}

pub fn build_config_owned(sections: Vec<Section>) -> Result<Config, ConfigError> {
    build_config_inputs::<OwnedMode>(sections.into_iter().map(owned))
}

fn build_config_inputs<'a, M: InputMode>(
    sections: impl Iterator<Item = M::Value<'a, Section>>,
) -> Result<Config, ConfigError> {
    let mut global_section = None;
    let mut subscription_section = None;
    let mut node_section = None;
    let mut group_section = None;
    let mut routing_section = None;
    let mut dns_section = None;
    let mut unknown_section = None;

    for section in sections {
        match section.get().name.as_str() {
            "global" => global_section = Some(section),
            "subscription" => subscription_section = Some(section),
            "node" => node_section = Some(section),
            "group" => group_section = Some(section),
            "routing" => routing_section = Some(section),
            "dns" => dns_section = Some(section),
            "include" => {}
            name => unknown_section = Some(name.to_owned()),
        }
    }

    let global = match global_section {
        Some(section) => parse_global::<M>(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"global\": {err}")))?,
        None => {
            return Err(ConfigError::Build(
                "section global is required but not provided".to_owned(),
            ));
        }
    };

    let subscription = match subscription_section {
        Some(section) => parse_string_section::<M>(section).map_err(|err| {
            ConfigError::Build(format!("failed to parse \"subscription\": {err}"))
        })?,
        None => Vec::new(),
    };

    let node = match node_section {
        Some(section) => parse_string_section::<M>(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"node\": {err}")))?,
        None => Vec::new(),
    };

    let group = match group_section {
        Some(section) => parse_group_section::<M>(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"group\": {err}")))?,
        None => Vec::new(),
    };

    let routing = match routing_section {
        Some(section) => parse_routing::<M>(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"routing\": {err}")))?,
        None => {
            return Err(ConfigError::Build(
                "section routing is required but not provided".to_owned(),
            ));
        }
    };

    let dns = match dns_section {
        Some(section) => parse_dns::<M>(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"dns\": {err}")))?,
        None => Dns::default(),
    };

    if let Some(name) = unknown_section {
        return Err(ConfigError::Build(format!("unknown section: {name}")));
    }

    let mut config = Config {
        global,
        subscription,
        node,
        group,
        routing,
        dns,
    };
    patch_fallback_resolver(&config)?;
    patch_tcp_check_http_method(&mut config);
    patch_empty_dns(&mut config);
    patch_must_outbound(&mut config)?;
    Ok(config)
}
