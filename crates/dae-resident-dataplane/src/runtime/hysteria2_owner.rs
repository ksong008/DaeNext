pub(crate) use dae_resident_transport::{
    Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, start_hysteria2_owner_registry,
    start_hysteria2_owner_registry_on,
};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dae_runtime_control::OwnerGeneration;

    use crate::plan::build_resident_proxy_plan_for_node;

    fn owner_identity_for_link(link: String) -> [u8; 32] {
        let sections = dae_config::parser::parse_config(
            r#"
            global {
            allow_insecure: false
            }
            routing {
            fallback: direct
            }
            "#,
        )
        .unwrap();
        let config = dae_config::schema::build_config(&sections).unwrap();
        let mut proxy = build_resident_proxy_plan_for_node(
            &config,
            "owner-identity".to_owned(),
            "owner-identity-node".to_owned(),
            link,
        )
        .unwrap();
        proxy.materialize_execution();
        let binding = dae_resident_plan::ResidentProxyBinding::resident(
            Arc::new(proxy),
            OwnerGeneration::new(41),
        )
        .expect("materialized Hysteria2 owner identity test binding");
        dae_resident_transport::hysteria2_owner_identity_digest_for_test(&binding)
    }

    #[test]
    fn owner_identity_uses_effective_tls_policy_instead_of_insecure_text_shape() {
        let pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let absent =
            owner_identity_for_link("hysteria2://auth@example.com:443#owner-identity".to_owned());
        let explicit_false = owner_identity_for_link(
            "hysteria2://auth@example.com:443?insecure=false#owner-identity".to_owned(),
        );
        let explicit_true = owner_identity_for_link(
            "hysteria2://auth@example.com:443?insecure=true#owner-identity".to_owned(),
        );
        let absent_pin = owner_identity_for_link(format!(
            "hysteria2://auth@example.com:443?pinSHA256={pin}#owner-identity"
        ));
        let explicit_false_pin = owner_identity_for_link(format!(
            "hysteria2://auth@example.com:443?insecure=false&pinSHA256={pin}#owner-identity"
        ));

        assert_eq!(absent, explicit_false);
        assert_ne!(absent, explicit_true);
        assert_eq!(absent_pin, explicit_false_pin);
        assert_ne!(absent, absent_pin);
    }
}
