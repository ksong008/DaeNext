use super::{ResidentProtocolShape, ResidentStreamWrapperPlan};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentTcpCarrierOwnership {
    PerFlowUnframed,
    PerFlowWrapped,
    GenerationFramed,
    GenerationMultiplexed,
}

impl ResidentTcpCarrierOwnership {
    pub(super) const fn from_execution(
        protocol: ResidentProtocolShape,
        wrapper: ResidentStreamWrapperPlan,
    ) -> Self {
        match protocol {
            ResidentProtocolShape::AnyTls => Self::GenerationFramed,
            ResidentProtocolShape::VlessMux
            | ResidentProtocolShape::Hysteria2
            | ResidentProtocolShape::Tuic
            | ResidentProtocolShape::Juicity => Self::GenerationMultiplexed,
            ResidentProtocolShape::VlessStandard
                if matches!(wrapper, ResidentStreamWrapperPlan::Meek) =>
            {
                Self::GenerationFramed
            }
            ResidentProtocolShape::VlessStandard
            | ResidentProtocolShape::Trojan
            | ResidentProtocolShape::VmessAead
                if matches!(
                    wrapper,
                    ResidentStreamWrapperPlan::Grpc
                        | ResidentStreamWrapperPlan::H2
                        | ResidentStreamWrapperPlan::Xhttp(_)
                ) =>
            {
                Self::GenerationMultiplexed
            }
            _ if matches!(
                wrapper,
                ResidentStreamWrapperPlan::TcpHttpHeader
                    | ResidentStreamWrapperPlan::HttpTransport
                    | ResidentStreamWrapperPlan::WebSocket
                    | ResidentStreamWrapperPlan::HttpUpgrade
                    | ResidentStreamWrapperPlan::SimpleObfsHttp
                    | ResidentStreamWrapperPlan::SimpleObfsTls
                    | ResidentStreamWrapperPlan::LegacyObfs
                    | ResidentStreamWrapperPlan::V2rayPluginTlsWebSocket
            ) =>
            {
                Self::PerFlowWrapped
            }
            _ => Self::PerFlowUnframed,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) const fn as_str(
        self,
    ) -> &'static str {
        match self {
            Self::PerFlowUnframed => "per-flow-unframed",
            Self::PerFlowWrapped => "per-flow-wrapped",
            Self::GenerationFramed => "generation-framed",
            Self::GenerationMultiplexed => "generation-multiplexed",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) const fn cross_flow_reuse(
        self,
    ) -> bool {
        matches!(self, Self::GenerationFramed | Self::GenerationMultiplexed)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn json(self) -> Value {
        let per_flow = !self.cross_flow_reuse();
        json!({
            "schemaVersion": 1,
            "ownership": self.as_str(),
            "physicalCarrierScope": if per_flow { "flow" } else { "generation-complete-transport-key" },
            "logicalStreamScope": if per_flow { "same-as-physical-flow" } else { "protocol-framed-logical-stream" },
            "crossFlowCarrierReuse": self.cross_flow_reuse(),
            "carrierReuseMode": match self {
                Self::PerFlowUnframed | Self::PerFlowWrapped => "none",
                Self::GenerationFramed => "bounded-sequential-or-exchange-framed",
                Self::GenerationMultiplexed => "protocol-multiplexed",
            },
            "unframedLiveStreamSharing": false,
            "flowCloseIsolation": if per_flow { "physical-stream-per-flow" } else { "protocol-logical-stream" },
            "sharedTlsMaterial": if per_flow { "config-verifier-ticket-material-only" } else { "complete-key-carrier-owner" },
            "halfCloseScope": if per_flow { "per-flow-relay" } else { "protocol-logical-stream" },
            "routingEvidenceScope": "per-flow",
            "errorEvidenceScope": "per-flow-or-physical-fanout",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::plan::ResidentXhttpHttpVersion;

    #[test]
    fn unframed_and_per_flow_wrappers_never_enter_shared_carriers() {
        use ResidentProtocolShape as Protocol;
        use ResidentStreamWrapperPlan as Wrapper;

        let unframed = [
            Protocol::Socks5,
            Protocol::HttpProxy,
            Protocol::ShadowsocksAead,
            Protocol::Shadowsocks2022,
            Protocol::VlessStandard,
            Protocol::VlessVision,
            Protocol::Trojan,
            Protocol::TrojanInnerShadowsocks,
            Protocol::VmessAead,
        ];
        for protocol in unframed {
            let ownership = ResidentTcpCarrierOwnership::from_execution(protocol, Wrapper::None);
            assert_eq!(ownership, ResidentTcpCarrierOwnership::PerFlowUnframed);
            assert!(!ownership.cross_flow_reuse());
        }

        for (protocol, wrapper) in [
            (Protocol::ShadowsocksSimpleObfsHttp, Wrapper::SimpleObfsHttp),
            (Protocol::ShadowsocksSimpleObfsTls, Wrapper::SimpleObfsTls),
            (
                Protocol::ShadowsocksV2rayPluginTlsWebSocket,
                Wrapper::V2rayPluginTlsWebSocket,
            ),
            (
                Protocol::Shadowsocks2022SimpleObfsHttp,
                Wrapper::SimpleObfsHttp,
            ),
            (Protocol::ShadowsocksRHttpSimple, Wrapper::LegacyObfs),
        ] {
            let ownership = ResidentTcpCarrierOwnership::from_execution(protocol, wrapper);
            assert_eq!(ownership, ResidentTcpCarrierOwnership::PerFlowWrapped);
            assert!(!ownership.cross_flow_reuse());
        }

        for protocol in [
            Protocol::VlessStandard,
            Protocol::Trojan,
            Protocol::VmessAead,
        ] {
            for wrapper in [Wrapper::WebSocket, Wrapper::HttpUpgrade] {
                let ownership = ResidentTcpCarrierOwnership::from_execution(protocol, wrapper);
                assert_eq!(ownership, ResidentTcpCarrierOwnership::PerFlowWrapped);
                assert!(!ownership.cross_flow_reuse());
            }
        }
    }

    #[test]
    fn only_protocol_framed_transports_enter_generation_carriers() {
        use ResidentProtocolShape as Protocol;
        use ResidentStreamWrapperPlan as Wrapper;

        for (protocol, wrapper) in [
            (Protocol::VlessMux, Wrapper::Mux),
            (Protocol::Hysteria2, Wrapper::None),
            (Protocol::Tuic, Wrapper::None),
            (Protocol::Juicity, Wrapper::None),
            (Protocol::VlessStandard, Wrapper::Grpc),
            (Protocol::VlessStandard, Wrapper::H2),
            (
                Protocol::VlessStandard,
                Wrapper::Xhttp(ResidentXhttpHttpVersion::H3),
            ),
            (Protocol::Trojan, Wrapper::Grpc),
            (Protocol::VmessAead, Wrapper::Grpc),
            (Protocol::VmessAead, Wrapper::H2),
        ] {
            let ownership = ResidentTcpCarrierOwnership::from_execution(protocol, wrapper);
            assert_eq!(
                ownership,
                ResidentTcpCarrierOwnership::GenerationMultiplexed
            );
            assert!(ownership.cross_flow_reuse());
            assert_eq!(ownership.json()["unframedLiveStreamSharing"], false);
        }

        for (protocol, wrapper) in [
            (Protocol::AnyTls, Wrapper::FrameStream),
            (Protocol::VlessStandard, Wrapper::Meek),
        ] {
            let ownership = ResidentTcpCarrierOwnership::from_execution(protocol, wrapper);
            assert_eq!(ownership, ResidentTcpCarrierOwnership::GenerationFramed);
            assert!(ownership.cross_flow_reuse());
            assert_eq!(ownership.json()["unframedLiveStreamSharing"], false);
        }
    }
}
