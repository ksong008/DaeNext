use super::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ConnectUdpH3PoolKey {
    pub(super) generation: u64,
    group_name: String,
    node_tag: String,
    graph_link_hash: String,
    server_host: String,
    server_port: u16,
    server_name: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    authentication_identity: [u8; 32],
    target_template: String,
    mark: u32,
}

impl ConnectUdpH3PoolKey {
    pub(super) fn from_proxy(
        proxy: &ResidentProxyPlan,
    ) -> Result<(Self, ResidentConnectUdpRuntimePlan), String> {
        let plan = connect_udp_h3_plan(proxy)?;
        if proxy.tls != "quic"
            || proxy.alpn.as_slice() != ["h3"]
            || proxy.tls_fragment.is_some()
            || proxy.utls_fingerprint.is_some()
            || proxy.reality.is_some()
            || proxy.mptcp
        {
            return Err(
                "CONNECT-UDP H3 requires the explicit QUIC TLS + ALPN h3 source contract"
                    .to_owned(),
            );
        }
        Ok((
            Self {
                generation: plan.runtime.generation,
                group_name: proxy.group_name.clone(),
                node_tag: proxy.node_tag.clone(),
                graph_link_hash: proxy.graph_link_hash.clone(),
                server_host: proxy.server_host.clone(),
                server_port: proxy.server_port,
                server_name: proxy.server_name.clone(),
                alpn: proxy.alpn.clone(),
                allow_insecure: proxy.allow_insecure,
                authentication_identity: connect_udp_authentication_identity(plan.authentication),
                target_template: plan.target_template.as_str().to_owned(),
                mark: proxy.mark,
            },
            plan.runtime,
        ))
    }
}
