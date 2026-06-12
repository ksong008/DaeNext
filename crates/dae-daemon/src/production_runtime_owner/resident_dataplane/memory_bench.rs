use super::plan::{ResidentProxyGroupPlan, build_resident_dataplane_plan};

pub struct ResidentTcpSelectionBenchmarkFixture {
    group: ResidentProxyGroupPlan,
    mark: u32,
    mptcp: bool,
}

impl ResidentTcpSelectionBenchmarkFixture {
    pub fn run_once(&self) -> u64 {
        let mut proxy = self
            .group
            .select_proxy_for_tcp()
            .expect("resident TCP benchmark proxy selection");
        proxy.mark = self.mark;
        proxy.mptcp = self.mptcp;
        let chain_checksum = proxy
            .chain_parent
            .as_ref()
            .map(|parent| parent.node_tag.len() as u64 ^ parent.server_host.len() as u64)
            .unwrap_or(0);
        proxy.graph_id.len() as u64
            ^ ((proxy.graph_link_hash.len() as u64) << 1)
            ^ ((proxy.redacted_link_source.len() as u64) << 2)
            ^ ((proxy.protocol.len() as u64) << 3)
            ^ ((proxy.group_name.len() as u64) << 4)
            ^ ((proxy.group_policy.len() as u64) << 5)
            ^ ((proxy.node_tag.len() as u64) << 6)
            ^ ((proxy.server_host.len() as u64) << 7)
            ^ ((proxy.server_port as u64) << 8)
            ^ ((proxy.server_name.len() as u64) << 9)
            ^ ((proxy.alpn.iter().map(|item| item.len()).sum::<usize>() as u64) << 10)
            ^ ((proxy.flow.len() as u64) << 11)
            ^ ((proxy.net.len() as u64) << 12)
            ^ ((proxy.stream_host.len() as u64) << 13)
            ^ ((proxy.stream_path.len() as u64) << 14)
            ^ ((proxy.tls.len() as u64) << 15)
            ^ ((proxy.allow_insecure as u64) << 16)
            ^ ((proxy.mark as u64) << 17)
            ^ ((proxy.mptcp as u64) << 18)
            ^ chain_checksum
    }
}

pub fn resident_tcp_selection_benchmark_fixture()
-> Result<ResidentTcpSelectionBenchmarkFixture, String> {
    let config = resident_tcp_selection_benchmark_config()?;
    let plan = build_resident_dataplane_plan(&config)?;
    let group = plan
        .default_proxy_group()
        .cloned()
        .ok_or_else(|| "resident TCP benchmark fixture has no default proxy group".to_owned())?;
    Ok(ResidentTcpSelectionBenchmarkFixture {
        group,
        mark: 0x55aa,
        mptcp: true,
    })
}

fn resident_tcp_selection_benchmark_config() -> Result<dae_config::Config, String> {
    let source = r#"
        global {
            lan_interface: daerust0
            allow_insecure: true
            so_mark_from_dae: 1234
            mptcp: true
        }
        node {
            socks_live: 'socks5://identity-1:credential-1@node-1.fixture.invalid:28001'
        }
        group {
            proxy {
                filter: name(socks_live)
                policy: fixed(0)
            }
        }
        routing {
            l4proto(tcp) && dport(443) -> proxy
            fallback: direct
        }
    "#;
    let sections = dae_config::parser::parse_config(source).map_err(|err| err.to_string())?;
    dae_config::schema::build_config(&sections).map_err(|err| err.to_string())
}
