use super::{
    ResidentProtocolShape, ResidentProxyPlan, ResidentSecurityUnderlayPlan,
    ResidentStreamWrapperPlan,
};
#[cfg(test)]
use super::{ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentUdpChainAdmission {
    NotChained,
    ParentStream,
    Unsupported(&'static str),
}

impl ResidentUdpChainAdmission {
    pub const fn status(self) -> &'static str {
        match self {
            Self::NotChained | Self::ParentStream => "admitted",
            Self::Unsupported(_) => "fail-closed",
        }
    }

    pub const fn carrier(self) -> &'static str {
        match self {
            Self::NotChained => "direct-child",
            Self::ParentStream => "parent-connect-stream",
            Self::Unsupported(_) => "unsupported",
        }
    }

    pub const fn unsupported_reason(self) -> Option<&'static str> {
        match self {
            Self::Unsupported(reason) => Some(reason),
            Self::NotChained | Self::ParentStream => None,
        }
    }
}

pub fn resident_udp_chain_admission(proxy: &ResidentProxyPlan) -> ResidentUdpChainAdmission {
    if proxy.chain_parent.is_none() {
        return ResidentUdpChainAdmission::NotChained;
    }

    let execution = proxy.execution_plan();
    match execution.protocol {
        ResidentProtocolShape::VmessAead
            if execution.security == ResidentSecurityUnderlayPlan::None
                && matches!(
                    execution.wrapper,
                    ResidentStreamWrapperPlan::None
                        | ResidentStreamWrapperPlan::TcpHttpHeader
                        | ResidentStreamWrapperPlan::WebSocket
                        | ResidentStreamWrapperPlan::HttpUpgrade
                ) =>
        {
            ResidentUdpChainAdmission::ParentStream
        }
        _ => ResidentUdpChainAdmission::Unsupported(
            "chained UDP is admitted only when the child packet protocol is carried entirely by the parent CONNECT stream; this child opens an independent packet path",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        let mut proxy = ResidentProxyPlan {
            graph_id: "graph".to_owned(),
            graph_link_hash: "hash".to_owned(),
            redacted_link_source: "source".to_owned(),
            protocol: "test",
            group_name: "group".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "node".to_owned(),
            server_host: String::new(),
            server_port: 0,
            server_name: String::new(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: "none".to_owned(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            ech: None,
            reality: None,
            handler,
            execution: None,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        proxy.materialize_execution();
        proxy
    }

    fn chained(mut child: ResidentProxyPlan) -> ResidentProxyPlan {
        child.chain_parent = Some(Arc::new(proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        })));
        child
    }

    #[test]
    fn only_complete_packet_over_stream_child_is_admitted() {
        let vmess = chained(proxy(ResidentProxyProtocolPlan::VmessAeadTcp {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            body_security: dae_outbound::vmess::VMessBodySecurity::Aes128Gcm,
        }));
        assert_eq!(
            resident_udp_chain_admission(&vmess),
            ResidentUdpChainAdmission::ParentStream
        );

        let mut vmess_http = proxy(ResidentProxyProtocolPlan::VmessAeadTcp {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            body_security: dae_outbound::vmess::VMessBodySecurity::Aes128Gcm,
        });
        vmess_http.net = "tcp-http-header".to_owned();
        vmess_http.execution = None;
        vmess_http.materialize_execution();
        assert_eq!(
            resident_udp_chain_admission(&chained(vmess_http)),
            ResidentUdpChainAdmission::ParentStream
        );

        let socks = chained(proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        }));
        assert!(matches!(
            resident_udp_chain_admission(&socks),
            ResidentUdpChainAdmission::Unsupported(_)
        ));
    }
}
