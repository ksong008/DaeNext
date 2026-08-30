#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableNodeKey(String);

impl StableNodeKey {
    pub fn from_link(link: &str) -> Self {
        Self(dae_outbound_stream::canonical_link_without_display_name(
            link,
        ))
    }

    pub fn from_canonical(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::StableNodeKey;
    use dae_product_core::RuntimeNodeTag;

    #[test]
    fn stable_key_ignores_only_the_display_fragment_for_generic_urls() {
        let first = StableNodeKey::from_link("socks://127.0.0.1:1080#first");
        let renamed = StableNodeKey::from_link("socks://127.0.0.1:1080#renamed");
        let changed = StableNodeKey::from_link("socks://127.0.0.1:1081#renamed");
        assert_eq!(first, renamed);
        assert_ne!(first, changed);
    }

    #[test]
    fn runtime_tag_is_deterministic_and_node_id_scoped() {
        assert_eq!(
            RuntimeNodeTag::from_node_id(41),
            RuntimeNodeTag::from_node_id(41)
        );
        assert_ne!(
            RuntimeNodeTag::from_node_id(41),
            RuntimeNodeTag::from_node_id(42)
        );
    }
}
