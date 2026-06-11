use super::*;
#[cfg(test)]
mod tests {
    use super::{
        OutboundDependencyBoundary, OutboundSplitDecision, OutboundSurface, RuntimeOwnerSurface,
        RuntimeOwnership, TEST_SUPPORT_DEPENDENCIES, crate_split_decision,
        dependency_boundary_contract, module_boundary_contract, public_api_contract,
        runtime_ownership_contract,
    };

    #[test]
    fn public_api_contract_excludes_fixture_support_and_smoke_surfaces() {
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
                .all(|item| !item.module.contains("fixture_support"))
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
            assert!(item.product_runtime_required);
        }

        let rcgen = TEST_SUPPORT_DEPENDENCIES
            .iter()
            .find(|item| item.crate_name == "rcgen")
            .unwrap();
        assert_eq!(rcgen.boundary, OutboundDependencyBoundary::TestSupport);
        assert!(!rcgen.product_runtime_required);
        assert_eq!(rcgen.feature_candidate, Some("test-support"));
    }

    #[test]
    fn module_contract_defers_physical_split_but_marks_transport_and_fixture_support_boundaries() {
        assert_eq!(crate_split_decision(), OutboundSplitDecision::KeepInCrate);
        let xhttp_h3 = module_boundary_contract()
            .iter()
            .find(|item| item.module == "shared_transport::xhttp_h3")
            .unwrap();
        assert_eq!(xhttp_h3.surface, OutboundSurface::Transport);
        assert_eq!(xhttp_h3.split_decision, OutboundSplitDecision::ExtractLater);

        let fixture_support_tests = module_boundary_contract()
            .iter()
            .find(|item| item.module == "tests::*fixture_support*")
            .unwrap();
        assert_eq!(fixture_support_tests.surface, OutboundSurface::TestSupport);
        assert_eq!(
            fixture_support_tests.split_decision,
            OutboundSplitDecision::MoveToTestSupport
        );
    }

    #[test]
    fn product_runtime_ownership_does_not_allow_local_runtime_creation() {
        let product_entries: Vec<_> = runtime_ownership_contract()
            .iter()
            .filter(|item| item.final_native_product_path)
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
            assert!(!item.final_native_product_path);
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
        assert!(!h3_admission.final_native_product_path);
        assert!(!h3_admission.local_runtime_allowed);
    }
}
