use super::parser::*;
use super::patch::*;
use super::*;

pub fn build_config(sections: &[Section]) -> Result<Config, ConfigError> {
    let mut name_to_section: HashMap<&str, (&Section, bool)> = HashMap::new();
    for section in sections {
        name_to_section.insert(section.name.as_str(), (section, false));
    }

    let global = match name_to_section.get_mut("global") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_global(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"global\": {err}")))?
        }
        None => {
            return Err(ConfigError::Build(
                "section global is required but not provided".to_owned(),
            ));
        }
    };

    let subscription = match name_to_section.get_mut("subscription") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_string_section(section).map_err(|err| {
                ConfigError::Build(format!("failed to parse \"subscription\": {err}"))
            })?
        }
        None => Vec::new(),
    };

    let node = match name_to_section.get_mut("node") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_string_section(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"node\": {err}")))?
        }
        None => Vec::new(),
    };

    let group = match name_to_section.get_mut("group") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_group_section(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"group\": {err}")))?
        }
        None => Vec::new(),
    };

    let routing = match name_to_section.get_mut("routing") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_routing(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"routing\": {err}")))?
        }
        None => {
            return Err(ConfigError::Build(
                "section routing is required but not provided".to_owned(),
            ));
        }
    };

    let dns = match name_to_section.get_mut("dns") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_dns(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"dns\": {err}")))?
        }
        None => Dns::default(),
    };

    for (name, (section, parsed)) in name_to_section {
        if section.name == "include" {
            continue;
        }
        if !parsed {
            return Err(ConfigError::Build(format!("unknown section: {name}")));
        }
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

pub fn build_config_owned(sections: Vec<Section>) -> Result<Config, ConfigError> {
    let mut name_to_section: HashMap<String, Section> = HashMap::new();
    for section in sections {
        name_to_section.insert(section.name.clone(), section);
    }

    let global = match name_to_section.remove("global") {
        Some(section) => parse_global_owned(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"global\": {err}")))?,
        None => {
            return Err(ConfigError::Build(
                "section global is required but not provided".to_owned(),
            ));
        }
    };

    let subscription = match name_to_section.remove("subscription") {
        Some(section) => parse_string_section_owned(section).map_err(|err| {
            ConfigError::Build(format!("failed to parse \"subscription\": {err}"))
        })?,
        None => Vec::new(),
    };

    let node = match name_to_section.remove("node") {
        Some(section) => parse_string_section_owned(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"node\": {err}")))?,
        None => Vec::new(),
    };

    let group = match name_to_section.remove("group") {
        Some(section) => parse_group_section_owned(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"group\": {err}")))?,
        None => Vec::new(),
    };

    let routing = match name_to_section.remove("routing") {
        Some(section) => parse_routing_owned(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"routing\": {err}")))?,
        None => {
            return Err(ConfigError::Build(
                "section routing is required but not provided".to_owned(),
            ));
        }
    };

    let dns = match name_to_section.remove("dns") {
        Some(section) => parse_dns_owned(section)
            .map_err(|err| ConfigError::Build(format!("failed to parse \"dns\": {err}")))?,
        None => Dns::default(),
    };

    name_to_section.remove("include");
    if let Some(name) = name_to_section.keys().next() {
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
