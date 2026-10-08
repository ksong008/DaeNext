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
    fn xhttp_download_password_identity_uses_effective_key_without_hiding_errors() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::json;

        let key = URL_SAFE_NO_PAD.encode([7; 32]);
        let other = URL_SAFE_NO_PAD.encode([8; 32]);
        let identity = |credentials: serde_json::Value| {
            let mut url =
                url::Url::parse("vless://01010101-0101-4101-8101-010101010101@node.example:443")
                    .unwrap();
            let extra = json!({"downloadSettings":{"address":"download.example","security":"reality","realitySettings":credentials}});
            url.query_pairs_mut().extend_pairs([
                ("type", "xhttp"),
                ("security", "tls"),
                ("extra", &extra.to_string()),
            ]);
            canonical_link_without_display_name(url.as_str())
        };
        let reference = identity(json!({"publicKey":key}));
        for credentials in [
            json!({"password":key}),
            json!({"password":key,"publicKey":key}),
            json!({"password":key,"publicKey":other}),
            json!({"password":"","publicKey":key}),
            json!({"password":key,"publicKey":"ignored"}),
        ] {
            assert_eq!(identity(credentials), reference);
        }
        assert_ne!(identity(json!({"password":other})), reference);
        for invalid in [
            json!("not!base64"),
            json!(42),
            json!(URL_SAFE_NO_PAD.encode([0; 31])),
        ] {
            let result = identity(json!({"password":invalid,"publicKey":key}));
            assert_ne!(result, reference);
            let link = VLESSLink::parse(&result).unwrap();
            let extra: serde_json::Value = serde_json::from_str(&link.xhttp_extra).unwrap();
            assert_eq!(
                extra["downloadSettings"]["realitySettings"]["password"],
                invalid
            );
        }
        assert_ne!(identity(json!({"password":key,"publicKey":42})), reference);
    }

    #[test]
    fn generic_url_identity_ignores_display_fragment_only() {
        let first = canonical_link_without_display_name("socks5://192.0.2.1:1080#first");
        let renamed = canonical_link_without_display_name("socks5://192.0.2.1:1080#renamed");
        let changed = canonical_link_without_display_name("socks5://192.0.2.1:1081#renamed");
        assert_eq!(first, renamed);
        assert_ne!(first, changed);
    }
}
