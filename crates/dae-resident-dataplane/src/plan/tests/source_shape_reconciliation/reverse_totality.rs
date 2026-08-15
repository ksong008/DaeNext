use super::*;
use dae_outbound::{
    MaterializedSecurity, MaterializedSourceShape, MaterializedTlsFeatures, MaterializedTlsVariant,
    SourceShapeReconciliationKind,
};

mod baseline;
mod chains;
mod classified;
mod dispositions;
mod quic;
mod stream_transports;
mod tls;
mod xhttp;

#[derive(Clone, Copy, Debug)]
enum TlsProfile {
    Standard,
    Insecure,
    InsecureFragment,
    Fragment,
    Fingerprint,
    InsecureFingerprint,
    FragmentFingerprint,
    InsecureFragmentFingerprint,
}

impl TlsProfile {
    const ALL: [Self; 8] = [
        Self::Standard,
        Self::Insecure,
        Self::InsecureFragment,
        Self::Fragment,
        Self::Fingerprint,
        Self::InsecureFingerprint,
        Self::FragmentFingerprint,
        Self::InsecureFragmentFingerprint,
    ];

    const WITHOUT_FINGERPRINT: [Self; 4] = [
        Self::Standard,
        Self::Insecure,
        Self::InsecureFragment,
        Self::Fragment,
    ];

    const ANYTLS: [Self; 4] = [
        Self::Standard,
        Self::Fragment,
        Self::Insecure,
        Self::InsecureFragment,
    ];

    fn allow_insecure(self) -> bool {
        matches!(
            self,
            Self::Insecure
                | Self::InsecureFragment
                | Self::InsecureFingerprint
                | Self::InsecureFragmentFingerprint
        )
    }

    fn fragment(self) -> bool {
        matches!(
            self,
            Self::InsecureFragment
                | Self::Fragment
                | Self::FragmentFingerprint
                | Self::InsecureFragmentFingerprint
        )
    }

    fn fingerprint(self) -> bool {
        matches!(
            self,
            Self::Fingerprint
                | Self::InsecureFingerprint
                | Self::FragmentFingerprint
                | Self::InsecureFragmentFingerprint
        )
    }

    fn link_fingerprint(self) -> &'static str {
        if self.fingerprint() { "chrome" } else { "" }
    }

    fn expected_variant(self) -> MaterializedTlsVariant {
        let features = MaterializedTlsFeatures::new(
            self.allow_insecure(),
            self.fragment(),
            self.fingerprint(),
        );
        let security = if self.fingerprint() {
            MaterializedSecurity::FingerprintAwareTls
        } else if self.allow_insecure() {
            MaterializedSecurity::InsecureTls
        } else if self.fragment() {
            MaterializedSecurity::FragmentedTls
        } else {
            MaterializedSecurity::StandardTls
        };
        MaterializedTlsVariant::new(security, features)
    }
}

fn config_for(profile: TlsProfile) -> Config {
    let tls_implementation = if profile.fingerprint() { "utls" } else { "tls" };
    let fragment = if profile.fragment() {
        "tls_fragment: true\ntls_fragment_length: 1-4\ntls_fragment_interval: 1-1"
    } else {
        "tls_fragment: false"
    };
    parse_config(&format!(
        r#"
        global {{
          lan_interface: daerust0
          allow_insecure: false
          so_mark_from_dae: 1234
          mptcp: false
          tls_implementation: {tls_implementation}
          utls_imitate: chrome_102
          {fragment}
        }}
        routing {{
          fallback: direct
        }}
        "#
    ))
}

fn assert_exact_tls_source(source: String, profile: TlsProfile, expected_ids: &[&str]) {
    let config = config_for(profile);
    let shape = assert_exact_source(&source, &config, expected_ids);
    assert_eq!(
        shape.tls_variant(),
        profile.expected_variant(),
        "{profile:?}"
    );
}

fn assert_exact_source(
    source: &str,
    config: &Config,
    expected_ids: &[&str],
) -> MaterializedSourceShape {
    let proxy = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "reverse-totality".to_owned(),
        source.to_owned(),
    )
    .unwrap_or_else(|error| panic!("builder must admit reverse-totality source: {error}"));
    let shape = materialized_source_shape(&proxy, source);
    let actual_ids = production_match_ids(source, &proxy);
    let mut expected_ids = expected_ids.to_vec();
    expected_ids.sort_unstable();
    assert_eq!(actual_ids, expected_ids, "{shape:?}");
    shape
}

fn production_match_ids(source: &str, proxy: &ResidentProxyPlan) -> Vec<&'static str> {
    let parsed = dae_outbound::parse_link_chain(source).unwrap();
    let node = ResidentNodeLinkShape {
        tag: "reverse-totality".to_owned(),
        scheme: parsed.nodes.first().unwrap().scheme.clone(),
        link: source.to_owned(),
    };
    let mut ids = dae_outbound::source_shape_registry_rows()
        .iter()
        .filter(|row| {
            source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
                reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
            }) && source_shape_candidate_is_relevant(row, &node)
                && source_shape_matches_materialization(row, proxy, source)
        })
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}
