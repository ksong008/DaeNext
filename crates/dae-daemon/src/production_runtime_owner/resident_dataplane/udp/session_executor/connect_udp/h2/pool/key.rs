use sha2::{Digest, Sha256};

use super::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ConnectUdpH2PoolKey {
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
    mptcp: bool,
}

impl ConnectUdpH2PoolKey {
    pub(super) fn from_proxy(
        proxy: &ResidentProxyPlan,
    ) -> Result<(Self, ResidentConnectUdpRuntimePlan), String> {
        let plan = connect_udp_h2_plan(proxy)?;
        if proxy.tls != "tls"
            || proxy.alpn.as_slice() != ["h2"]
            || proxy.tls_fragment.is_some()
            || proxy.utls_fingerprint.is_some()
            || proxy.reality.is_some()
        {
            return Err(
                "CONNECT-UDP H2 requires the explicit standard TLS + ALPN h2 source contract"
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
                authentication_identity: authentication_identity(plan.authentication),
                target_template: plan.target_template.as_str().to_owned(),
                mark: proxy.mark,
                mptcp: proxy.mptcp,
            },
            plan.runtime,
        ))
    }
}

fn authentication_identity(authentication: &ResidentConnectUdpAuthPlan) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match authentication {
        ResidentConnectUdpAuthPlan::None => hasher.update(b"none"),
        ResidentConnectUdpAuthPlan::Basic { username, password } => {
            hasher.update(b"basic\0");
            hasher.update((username.len() as u64).to_be_bytes());
            hasher.update(username.as_bytes());
            hasher.update((password.len() as u64).to_be_bytes());
            hasher.update(password.as_bytes());
        }
    }
    hasher.finalize().into()
}
