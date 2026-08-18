#[cfg(test)]
#[allow(clippy::module_inception)]
pub(in crate::udp) mod tests {
    use dae_outbound::shared_transport::GrpcMode;
    use dae_resident_plan::{
        ResidentProxyPlan, ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan,
    };

    pub(in crate::udp) fn test_udp_proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        let mut proxy = ResidentProxyPlan {
            graph_id: "resident-graph:redacted".to_owned(),
            graph_link_hash: "sha256:redacted".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "redacted",
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "redacted".to_owned(),
            server_host: String::new(),
            server_port: 0,
            server_name: String::new(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            grpc_mode: GrpcMode::Gun,
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: String::new(),
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
}
