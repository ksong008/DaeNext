use super::*;
use crate::source_shape_registry::RuntimeOwnershipModel;

impl MaterializedSourceShape {
    pub fn runtime_ownership_model(self) -> RuntimeOwnershipModel {
        match (self.chain, self.chain_udp) {
            (MaterializedChain::ParentConnect, MaterializedChainUdp::ParentStream) => {
                return RuntimeOwnershipModel::FlowStreamAndPacketSession;
            }
            (MaterializedChain::ParentConnect, MaterializedChainUdp::PolicyClosed) => {
                return RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed;
            }
            (MaterializedChain::ParentConnect, MaterializedChainUdp::NotChained)
            | (MaterializedChain::Standalone, MaterializedChainUdp::ParentStream)
            | (MaterializedChain::Standalone, MaterializedChainUdp::PolicyClosed) => {
                return RuntimeOwnershipModel::MaterializedShapeRejected;
            }
            (MaterializedChain::Standalone, MaterializedChainUdp::NotChained) => {}
        }

        match self.protocol {
            MaterializedProtocol::Socks5 => RuntimeOwnershipModel::FlowStreamAndAssociation,
            MaterializedProtocol::Hysteria2 => {
                RuntimeOwnershipModel::GenerationOwnedHysteria2Transport
            }
            MaterializedProtocol::Tuic => RuntimeOwnershipModel::GenerationOwnedTuicTransport,
            MaterializedProtocol::Juicity => RuntimeOwnershipModel::GenerationOwnedJuicityTransport,
            MaterializedProtocol::ConnectUdpH2 | MaterializedProtocol::ConnectUdpH3 => {
                RuntimeOwnershipModel::GenerationConnectUdpTransport
            }
            MaterializedProtocol::VlessStandard
                if matches!(
                    self.wrapper,
                    MaterializedWrapper::XhttpH1
                        | MaterializedWrapper::XhttpH2
                        | MaterializedWrapper::XhttpH3
                ) =>
            {
                RuntimeOwnershipModel::ConfiguredHttpTransport
            }
            MaterializedProtocol::VlessStandard if self.wrapper == MaterializedWrapper::Meek => {
                RuntimeOwnershipModel::GenerationOwnedMeekTransport
            }
            _ if matches!(self.udp, MaterializedUdp::PolicyClosed(_)) => {
                RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed
            }
            _ => RuntimeOwnershipModel::FlowStreamAndPacketSession,
        }
    }
}
