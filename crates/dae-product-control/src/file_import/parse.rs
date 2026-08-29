use super::*;
use dae_config::{Item, Section};

pub(super) struct ParsedDaeFile {
    pub(super) sections: Vec<Section>,
    pub(super) config: Config,
}

pub(super) fn parse_dae_file(content: &str) -> io::Result<ParsedDaeFile> {
    if content.trim().is_empty() {
        return Err(invalid_dae_file("dae config file content is empty"));
    }
    let sections = parse_config(content)
        .map_err(|err| invalid_dae_file(format!("parse dae config file: {err}")))?;
    reject_duplicate_sections(&sections)?;
    reject_external_or_embedded_subscriptions(&sections)?;
    let config = build_config(&sections)
        .map_err(|err| invalid_dae_file(format!("build dae config file: {err}")))?;
    Ok(ParsedDaeFile { sections, config })
}

fn reject_duplicate_sections(sections: &[Section]) -> io::Result<()> {
    let mut seen = HashSet::new();
    for section in sections {
        if !seen.insert(section.name.as_str()) {
            return Err(invalid_dae_file(format!(
                "duplicate top-level section {:?} is ambiguous",
                section.name
            )));
        }
    }
    Ok(())
}

fn reject_external_or_embedded_subscriptions(sections: &[Section]) -> io::Result<()> {
    for section in sections {
        match section.name.as_str() {
            "include" => {
                return Err(invalid_dae_file(
                    "include sections cannot be imported as a self-contained dae file",
                ));
            }
            "subscription" if section.items.iter().any(subscription_item_has_value) => {
                return Err(invalid_dae_file(
                    "subscription entries must be imported through product subscription resources",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn subscription_item_has_value(item: &Item) -> bool {
    match item {
        Item::Param(param) => !param.key.trim().is_empty() || !param.val.trim().is_empty(),
        Item::Section(_) | Item::RoutingRule(_) => true,
    }
}
