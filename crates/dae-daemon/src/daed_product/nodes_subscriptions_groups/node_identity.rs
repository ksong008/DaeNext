#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StableNodeKey(String);

impl StableNodeKey {
    pub(crate) fn from_link(link: &str) -> Self {
        Self(canonical_link_without_display_name(link))
    }
}

fn canonical_link_without_display_name(link: &str) -> String {
    if let Ok(mut parsed) = dae_outbound::VMessLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::VLESSLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::TrojanLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::ShadowsocksLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::Hysteria2Link::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::TuicLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::JuicityLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    url_without_fragment(link)
}

fn url_without_fragment(link: &str) -> String {
    if let Ok(mut url) = url::Url::parse(link) {
        url.set_fragment(None);
        return url.to_string();
    }
    link.split_once('#')
        .map(|(without_fragment, _)| without_fragment.to_owned())
        .unwrap_or_else(|| link.to_owned())
}

#[cfg(test)]
mod tests {
    use super::StableNodeKey;

    #[test]
    fn stable_key_ignores_only_the_display_fragment_for_generic_urls() {
        let first = StableNodeKey::from_link("socks://127.0.0.1:1080#first");
        let renamed = StableNodeKey::from_link("socks://127.0.0.1:1080#renamed");
        let changed = StableNodeKey::from_link("socks://127.0.0.1:1081#renamed");
        assert_eq!(first, renamed);
        assert_ne!(first, changed);
    }
}
