use crate::{VLESSLink, VMessLink};
use dae_outbound_core::{Hysteria2Link, JuicityLink, ShadowsocksLink, TrojanLink, TuicLink};

/// Return the execution-relevant form of a share link.
///
/// Display names are deliberately excluded, while endpoint, authentication,
/// protocol, security, transport, and query parameters remain part of the
/// identity. Protocol parsers are used where a display name may live outside a
/// conventional URL fragment (notably VMess JSON links).
pub fn canonical_link_without_display_name(link: &str) -> String {
    if let Ok(mut parsed) = VMessLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = VLESSLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = TrojanLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = ShadowsocksLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = Hysteria2Link::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = TuicLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = JuicityLink::parse(link) {
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
    use super::*;

    #[test]
    fn generic_url_identity_ignores_display_fragment_only() {
        let first = canonical_link_without_display_name("socks5://192.0.2.1:1080#first");
        let renamed = canonical_link_without_display_name("socks5://192.0.2.1:1080#renamed");
        let changed = canonical_link_without_display_name("socks5://192.0.2.1:1081#renamed");
        assert_eq!(first, renamed);
        assert_ne!(first, changed);
    }
}
