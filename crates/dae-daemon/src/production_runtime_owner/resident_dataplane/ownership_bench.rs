use dae_runtime_control::OwnerGeneration;

use super::plan::{
    ResidentDataplanePlan, ResidentProxyBinding, ResidentProxyGroupPlan, ResidentProxyProtocolPlan,
    build_resident_dataplane_plan,
};
use super::transport_identity::resident_transport_binding_identity_digest;

const HEALTH_DESCRIPTOR_LARGE_CANDIDATES: usize = 128;
const OWNERSHIP_BENCHMARK_GENERATION: u64 = 73;
const UDP_ROUTE_MARK: u32 = 0x55aa;
const DNS_ROUTE_MARK: u32 = 0xaa55;
const TRANSPORT_HANDOFF_IDENTITY_DOMAIN: &[u8] = b"dae/transport-handoff-benchmark/v1";

pub struct ResidentProxyOwnershipBenchmarkFixture {
    plan: ResidentDataplanePlan,
    transport_binding: ResidentProxyBinding,
    health_one: ResidentProxyGroupPlan,
    health_ten: ResidentProxyGroupPlan,
    health_large: ResidentProxyGroupPlan,
}

impl ResidentProxyOwnershipBenchmarkFixture {
    pub fn default_binding_once(&self) -> u64 {
        let binding = self
            .plan
            .default_proxy_binding()
            .expect("resident ownership benchmark default binding");
        binding_checksum(&binding)
    }

    pub fn udp_route_binding_once(&self) -> u64 {
        let binding = self
            .plan
            .default_proxy_binding()
            .expect("resident ownership benchmark UDP binding")
            .with_route_socket_mark(UDP_ROUTE_MARK);
        binding_checksum(&binding) ^ u64::from(binding.effective_socket_mark())
    }

    pub fn dns_route_binding_once(&self) -> u64 {
        let binding = self
            .plan
            .default_proxy_binding()
            .expect("resident ownership benchmark DNS binding")
            .with_route_socket_mark(DNS_ROUTE_MARK);
        binding_checksum(&binding) ^ u64::from(binding.effective_socket_mark())
    }

    pub fn health_descriptors_one_once(&self) -> u64 {
        health_descriptor_checksum(&self.health_one)
    }

    pub fn health_descriptors_ten_once(&self) -> u64 {
        health_descriptor_checksum(&self.health_ten)
    }

    pub fn health_descriptors_large_once(&self) -> u64 {
        health_descriptor_checksum(&self.health_large)
    }

    pub fn transport_handoff_once(&self) -> u64 {
        let binding = self.transport_binding.clone();
        let digest =
            resident_transport_binding_identity_digest(TRANSPORT_HANDOFF_IDENTITY_DOMAIN, &binding);
        u64::from_be_bytes(digest[..8].try_into().expect("transport identity prefix"))
            ^ binding.runtime_generation().get()
            ^ u64::from(binding.effective_socket_mark())
    }

    pub fn credential_view_once(&self) -> u64 {
        let binding = self.transport_binding.clone();
        match &binding.plan().handler {
            ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
                username.len() as u64
                    ^ ((password.len() as u64) << 8)
                    ^ ((binding.plan().server_host.len() as u64) << 16)
            }
            _ => panic!("resident ownership benchmark expected SOCKS5 credentials"),
        }
    }
}

pub fn resident_proxy_ownership_benchmark_fixture()
-> Result<ResidentProxyOwnershipBenchmarkFixture, String> {
    let plan = benchmark_plan_with_candidates(1)?;
    let mut transport_binding = plan
        .default_proxy_binding()
        .ok_or_else(|| "resident ownership benchmark has no default binding".to_owned())?;
    transport_binding
        .bind_resident_generation(OwnerGeneration::new(OWNERSHIP_BENCHMARK_GENERATION))?;
    let health_one = benchmark_group_with_candidates(1)?;
    let health_ten = benchmark_group_with_candidates(10)?;
    let health_large = benchmark_group_with_candidates(HEALTH_DESCRIPTOR_LARGE_CANDIDATES)?;
    Ok(ResidentProxyOwnershipBenchmarkFixture {
        plan,
        transport_binding,
        health_one,
        health_ten,
        health_large,
    })
}

fn binding_checksum(binding: &ResidentProxyBinding) -> u64 {
    let plan = binding.plan();
    plan.graph_id.len() as u64
        ^ ((plan.node_tag.len() as u64) << 8)
        ^ ((plan.server_host.len() as u64) << 16)
        ^ (binding.runtime_generation().get() << 24)
        ^ ((u64::from(binding.effective_socket_mark())) << 32)
}

fn health_descriptor_checksum(group: &ResidentProxyGroupPlan) -> u64 {
    let descriptors = group.probe_candidates();
    let first = descriptors
        .first()
        .expect("resident ownership benchmark first health descriptor");
    let last = descriptors
        .last()
        .expect("resident ownership benchmark last health descriptor");
    descriptors.len() as u64
        ^ ((first.node_tag.len() as u64) << 8)
        ^ ((last.link_hash.len() as u64) << 16)
        ^ ((first.tcp_check.target.len() as u64) << 24)
}

fn benchmark_group_with_candidates(count: usize) -> Result<ResidentProxyGroupPlan, String> {
    benchmark_plan_with_candidates(count)?
        .default_proxy_group()
        .cloned()
        .ok_or_else(|| format!("resident ownership benchmark has no group for {count} candidates"))
}

fn benchmark_plan_with_candidates(count: usize) -> Result<ResidentDataplanePlan, String> {
    let mut source = String::from(
        r#"
        global {
            lan_interface: daerust0
            allow_insecure: true
            so_mark_from_dae: 1234
            mptcp: true
        }
        node {
        "#,
    );
    for index in 0..count {
        source.push_str(&format!(
            "node_{index:03}: 'socks5://identity-{index}:credential-{index}@127.0.0.1:{}'\n",
            28_000 + index
        ));
    }
    source.push_str(
        r#"
        }
        group {
            proxy {
                filter: name(regex: "^node_[0-9]+$")
                policy: fixed(0)
            }
        }
        routing {
            fallback: proxy
        }
        "#,
    );
    let sections = dae_config::parser::parse_config(&source).map_err(|err| err.to_string())?;
    let config = dae_config::schema::build_config(&sections).map_err(|err| err.to_string())?;
    build_resident_dataplane_plan(&config)
}
