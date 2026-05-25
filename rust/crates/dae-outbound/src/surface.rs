#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSurface {
    PublicApi,
    Core,
    Protocol,
    Dataplane,
    Transport,
    TestSupport,
    Admission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundDependencyBoundary {
    CoreRuntime,
    FormalTransport,
    TestSupport,
    BenchmarkOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSplitDecision {
    KeepInCrate,
    ExtractLater,
    MoveToTestSupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnerSurface {
    ProductDaemon,
    FormalTransport,
    Dataplane,
    LoopbackTestSupport,
    AdmissionHelper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnership {
    OwnedByDaemonRuntime,
    InjectedByCaller,
    MayCreateLocalRuntime,
    DependencyOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundModuleContract {
    pub module: &'static str,
    pub surface: OutboundSurface,
    pub split_decision: OutboundSplitDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundDependencyContract {
    pub crate_name: &'static str,
    pub boundary: OutboundDependencyBoundary,
    pub default_runtime_required: bool,
    pub feature_candidate: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeOwnershipContract {
    pub path: &'static str,
    pub surface: RuntimeOwnerSurface,
    pub ownership: RuntimeOwnership,
    pub default_product_path: bool,
    pub local_runtime_allowed: bool,
}

pub fn public_api_contract() -> &'static [OutboundModuleContract] {
    &PUBLIC_API_CONTRACT
}

pub fn module_boundary_contract() -> &'static [OutboundModuleContract] {
    &MODULE_BOUNDARY_CONTRACT
}

pub fn dependency_boundary_contract() -> &'static [OutboundDependencyContract] {
    &DEPENDENCY_BOUNDARY_CONTRACT
}

pub fn crate_split_decision() -> OutboundSplitDecision {
    OutboundSplitDecision::KeepInCrate
}

pub fn runtime_ownership_contract() -> &'static [RuntimeOwnershipContract] {
    &RUNTIME_OWNERSHIP_CONTRACT
}

const PUBLIC_API_CONTRACT: [OutboundModuleContract; 19] = [
    api("alive"),
    api("annotation"),
    api("connectivity"),
    api("dialer"),
    api("direct"),
    api("error"),
    api("filter"),
    api("group"),
    api("group_override"),
    api("latency"),
    api("link_parser"),
    api("policy"),
    api("types"),
    api("anytls"),
    api("http_proxy"),
    api("hysteria2"),
    api("juicity"),
    api("tuic"),
    api("vmess"),
];

const MODULE_BOUNDARY_CONTRACT: [OutboundModuleContract; 39] = [
    core("alive"),
    core("annotation"),
    core("connectivity"),
    core("dialer"),
    core("direct"),
    core("filter"),
    core("group"),
    core("group_override"),
    core("latency"),
    core("link_parser"),
    core("policy"),
    core("types"),
    protocol("anytls"),
    protocol("http_proxy"),
    protocol("hysteria2"),
    protocol("juicity"),
    protocol("shadowsocks"),
    protocol("socks5"),
    protocol("trojan"),
    protocol("tuic"),
    protocol("vless"),
    protocol("vmess"),
    transport("shared_transport"),
    transport("shared_transport::tls"),
    transport("shared_transport::grpc_http2"),
    transport("shared_transport::xhttp"),
    transport("shared_transport::xhttp_h3"),
    transport("shared_transport::quic_h3"),
    dataplane("anytls::dataplane"),
    dataplane("http_proxy::dataplane"),
    dataplane("hysteria2::dataplane"),
    dataplane("juicity::outbound_dataplane"),
    dataplane("shadowsocks::*_dataplane"),
    dataplane("socks5::dataplane"),
    dataplane("trojan::*_dataplane"),
    dataplane("tuic::dataplane"),
    dataplane("vless::dataplane"),
    dataplane("vmess::dataplane"),
    support("tests::*stage*"),
];

const DEPENDENCY_BOUNDARY_CONTRACT: [OutboundDependencyContract; 21] = [
    dep("aes", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "aes-gcm",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "base64",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "blake3",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("bytes", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "chacha20poly1305",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "dae-core-types",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("hkdf", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "http",
        OutboundDependencyBoundary::FormalTransport,
        true,
        None,
    ),
    dep("md-5", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("regex", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "rustls",
        OutboundDependencyBoundary::FormalTransport,
        true,
        None,
    ),
    dep(
        "serde_json",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("sha1", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("sha2", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("sha3", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("url", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "tokio",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("transport-runtime"),
    ),
    dep(
        "quinn",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
    dep(
        "h3",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
    dep(
        "h3-quinn",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
];

pub const TEST_SUPPORT_DEPENDENCIES: [OutboundDependencyContract; 2] = [
    dep(
        "rcgen",
        OutboundDependencyBoundary::TestSupport,
        false,
        Some("test-support"),
    ),
    dep(
        "dae-golden",
        OutboundDependencyBoundary::BenchmarkOnly,
        false,
        Some("test-support"),
    ),
];

const RUNTIME_OWNERSHIP_CONTRACT: [RuntimeOwnershipContract; 18] = [
    runtime_owner(
        "dae-daemon::production_runtime_owner",
        RuntimeOwnerSurface::ProductDaemon,
        RuntimeOwnership::OwnedByDaemonRuntime,
        true,
        false,
    ),
    runtime_owner(
        "dae-outbound::shared_transport",
        RuntimeOwnerSurface::FormalTransport,
        RuntimeOwnership::InjectedByCaller,
        true,
        false,
    ),
    runtime_owner(
        "dae-outbound::hysteria2::dataplane",
        RuntimeOwnerSurface::Dataplane,
        RuntimeOwnership::InjectedByCaller,
        true,
        false,
    ),
    runtime_owner(
        "dae-outbound::juicity::outbound_dataplane",
        RuntimeOwnerSurface::Dataplane,
        RuntimeOwnership::InjectedByCaller,
        true,
        false,
    ),
    runtime_owner(
        "dae-outbound::tuic::dataplane",
        RuntimeOwnerSurface::Dataplane,
        RuntimeOwnership::InjectedByCaller,
        true,
        false,
    ),
    runtime_owner(
        "dae-outbound::shared_transport::xhttp_h3::xhttp_h3_packet_up_loopback",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::hysteria2::quic_loopback::run_hysteria2_quic_loopback_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::tuic::quic_loopback::run_tuic_quic_loopback_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::h3_loopback::run_h3_loopback_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::auth_lifecycle::run_auth_lifecycle_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::auth_stream_ekm::run_live_ekm_auth_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::auth_stream_live::run_live_auth_stream_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::stream_packet_conn::run_stream_packet_conn_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::stream_packet_congestion::run_stream_packet_congestion_smoke",
        RuntimeOwnerSurface::LoopbackTestSupport,
        RuntimeOwnership::MayCreateLocalRuntime,
        false,
        true,
    ),
    runtime_owner(
        "dae-outbound::juicity::h3_admission::dependency_admission",
        RuntimeOwnerSurface::AdmissionHelper,
        RuntimeOwnership::DependencyOnly,
        false,
        false,
    ),
    runtime_owner(
        "dae-bench",
        RuntimeOwnerSurface::AdmissionHelper,
        RuntimeOwnership::InjectedByCaller,
        false,
        false,
    ),
    runtime_owner(
        "dae-cli::outbound_runner",
        RuntimeOwnerSurface::AdmissionHelper,
        RuntimeOwnership::InjectedByCaller,
        false,
        false,
    ),
    runtime_owner(
        "dae-cli::active_datapath_runner",
        RuntimeOwnerSurface::AdmissionHelper,
        RuntimeOwnership::InjectedByCaller,
        false,
        false,
    ),
];

const fn api(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::PublicApi,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

const fn core(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Core,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

const fn protocol(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Protocol,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

const fn transport(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Transport,
        split_decision: OutboundSplitDecision::ExtractLater,
    }
}

const fn dataplane(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Dataplane,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

const fn support(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::TestSupport,
        split_decision: OutboundSplitDecision::MoveToTestSupport,
    }
}

const fn dep(
    crate_name: &'static str,
    boundary: OutboundDependencyBoundary,
    default_runtime_required: bool,
    feature_candidate: Option<&'static str>,
) -> OutboundDependencyContract {
    OutboundDependencyContract {
        crate_name,
        boundary,
        default_runtime_required,
        feature_candidate,
    }
}

const fn runtime_owner(
    path: &'static str,
    surface: RuntimeOwnerSurface,
    ownership: RuntimeOwnership,
    default_product_path: bool,
    local_runtime_allowed: bool,
) -> RuntimeOwnershipContract {
    RuntimeOwnershipContract {
        path,
        surface,
        ownership,
        default_product_path,
        local_runtime_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OutboundDependencyBoundary, OutboundSplitDecision, OutboundSurface, RuntimeOwnerSurface,
        RuntimeOwnership, TEST_SUPPORT_DEPENDENCIES, crate_split_decision,
        dependency_boundary_contract, module_boundary_contract, public_api_contract,
        runtime_ownership_contract,
    };

    #[test]
    fn public_api_contract_excludes_stage_and_smoke_surfaces() {
        assert!(
            public_api_contract()
                .iter()
                .any(|item| item.module == "link_parser")
        );
        assert!(
            public_api_contract()
                .iter()
                .any(|item| item.module == "vmess")
        );
        assert!(
            public_api_contract()
                .iter()
                .all(|item| item.surface == OutboundSurface::PublicApi)
        );
        assert!(
            public_api_contract()
                .iter()
                .all(|item| !item.module.contains("stage"))
        );
        assert!(
            public_api_contract()
                .iter()
                .all(|item| !item.module.contains("loopback"))
        );
    }

    #[test]
    fn dependency_contract_keeps_runtime_transports_separate_from_test_support() {
        for name in ["quinn", "h3", "h3-quinn", "tokio", "rustls"] {
            let item = dependency_boundary_contract()
                .iter()
                .find(|item| item.crate_name == name)
                .unwrap();
            assert_eq!(item.boundary, OutboundDependencyBoundary::FormalTransport);
            assert!(item.default_runtime_required);
        }

        let rcgen = TEST_SUPPORT_DEPENDENCIES
            .iter()
            .find(|item| item.crate_name == "rcgen")
            .unwrap();
        assert_eq!(rcgen.boundary, OutboundDependencyBoundary::TestSupport);
        assert!(!rcgen.default_runtime_required);
        assert_eq!(rcgen.feature_candidate, Some("test-support"));
    }

    #[test]
    fn module_contract_defers_physical_split_but_marks_transport_and_stage_boundaries() {
        assert_eq!(crate_split_decision(), OutboundSplitDecision::KeepInCrate);
        let xhttp_h3 = module_boundary_contract()
            .iter()
            .find(|item| item.module == "shared_transport::xhttp_h3")
            .unwrap();
        assert_eq!(xhttp_h3.surface, OutboundSurface::Transport);
        assert_eq!(xhttp_h3.split_decision, OutboundSplitDecision::ExtractLater);

        let stage_tests = module_boundary_contract()
            .iter()
            .find(|item| item.module == "tests::*stage*")
            .unwrap();
        assert_eq!(stage_tests.surface, OutboundSurface::TestSupport);
        assert_eq!(
            stage_tests.split_decision,
            OutboundSplitDecision::MoveToTestSupport
        );
    }

    #[test]
    fn product_runtime_ownership_does_not_allow_local_runtime_creation() {
        let product_entries: Vec<_> = runtime_ownership_contract()
            .iter()
            .filter(|item| item.default_product_path)
            .collect();
        assert!(!product_entries.is_empty());

        for item in product_entries {
            assert_ne!(item.ownership, RuntimeOwnership::MayCreateLocalRuntime);
            assert!(!item.local_runtime_allowed);
        }
    }

    #[test]
    fn local_runtime_creation_is_limited_to_loopback_test_support() {
        let local_runtime_entries: Vec<_> = runtime_ownership_contract()
            .iter()
            .filter(|item| item.ownership == RuntimeOwnership::MayCreateLocalRuntime)
            .collect();
        assert_eq!(local_runtime_entries.len(), 9);

        for item in local_runtime_entries {
            assert_eq!(item.surface, RuntimeOwnerSurface::LoopbackTestSupport);
            assert!(item.local_runtime_allowed);
            assert!(!item.default_product_path);
        }
    }

    #[test]
    fn runtime_contract_covers_current_self_created_tokio_helpers() {
        let paths: Vec<_> = runtime_ownership_contract()
            .iter()
            .map(|item| item.path)
            .collect();

        for expected in [
            "dae-outbound::shared_transport::xhttp_h3::xhttp_h3_packet_up_loopback",
            "dae-outbound::hysteria2::quic_loopback::run_hysteria2_quic_loopback_smoke",
            "dae-outbound::tuic::quic_loopback::run_tuic_quic_loopback_smoke",
            "dae-outbound::juicity::h3_loopback::run_h3_loopback_smoke",
            "dae-outbound::juicity::auth_lifecycle::run_auth_lifecycle_smoke",
            "dae-outbound::juicity::auth_stream_ekm::run_live_ekm_auth_smoke",
            "dae-outbound::juicity::auth_stream_live::run_live_auth_stream_smoke",
            "dae-outbound::juicity::stream_packet_conn::run_stream_packet_conn_smoke",
            "dae-outbound::juicity::stream_packet_congestion::run_stream_packet_congestion_smoke",
        ] {
            assert!(
                paths.contains(&expected),
                "missing runtime owner: {expected}"
            );
        }
    }

    #[test]
    fn dependency_admission_does_not_claim_runtime_ownership() {
        let h3_admission = runtime_ownership_contract()
            .iter()
            .find(|item| item.path == "dae-outbound::juicity::h3_admission::dependency_admission")
            .unwrap();
        assert_eq!(h3_admission.surface, RuntimeOwnerSurface::AdmissionHelper);
        assert_eq!(h3_admission.ownership, RuntimeOwnership::DependencyOnly);
        assert!(!h3_admission.default_product_path);
        assert!(!h3_admission.local_runtime_allowed);
    }
}
