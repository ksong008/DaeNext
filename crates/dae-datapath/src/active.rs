pub const ACTIVE_TCP_DEFAULT_TARGET_IP: &str = "198.18.50.1";
pub const ACTIVE_TCP_DEFAULT_CLIENT_IP: &str = "10.220.50.2";
pub const ACTIVE_TCP_DEFAULT_TARGET_PORT: u16 = 18080;
pub const ACTIVE_TCP_DEFAULT_SO_MARK: u32 = 1234;
pub const ACTIVE_TCP_DEFAULT_MPTCP: bool = true;

pub const ACTIVE_TCP_CLIENT_NETNS: &str = "dae50client";
pub const ACTIVE_TCP_LAN_HOST_IFACE: &str = "dae50lan0";
pub const ACTIVE_TCP_LAN_CLIENT_IFACE: &str = "dae50cli0";
pub const ACTIVE_TCP_LAN_GATEWAY_IP: &str = "10.220.50.1";
pub const ACTIVE_TCP_LAN_FILTER_PREF: &str = "49501";
pub const ACTIVE_TCP_LAN_SECTION: &str = "tc/lan_ingress_l2";

pub const ACTIVE_TCP_ROUTING_MAP_KERNEL_NAME: &str = "routing_map";
pub const ACTIVE_TCP_ROUTING_MAP_KEY_SIZE: u32 = 4;
pub const ACTIVE_TCP_ROUTING_MAP_VALUE_SIZE: u32 = 24;
pub const ACTIVE_TCP_ROUTING_MAP_KEY: u32 = 0;
pub const ACTIVE_TCP_MATCH_TYPE_FALLBACK: u8 = 10;
pub const ACTIVE_TCP_OUTBOUND_PROXY: u8 = 2;

pub const ACTIVE_UDP_DEFAULT_TARGET_IP: &str = "198.18.53.1";
pub const ACTIVE_UDP_DEFAULT_TARGET_PORT: u16 = 18083;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveTcpTopologyContract {
    pub client_netns: &'static str,
    pub lan_host_iface: &'static str,
    pub lan_client_iface: &'static str,
    pub lan_gateway_ip: &'static str,
    pub lan_filter_pref: &'static str,
    pub lan_section: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveTcpRoutingMapContract {
    pub map_name: &'static str,
    pub key_size: u32,
    pub value_size: u32,
    pub key: u32,
    pub match_type: u8,
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveUdpEndpointContract {
    pub key_model: &'static str,
    pub nat_timeout_ms: i64,
    pub dns_nat_timeout_ms: i64,
    pub anyfrom_timeout_ms: i64,
    pub max_retry: i32,
    pub pool_max_entries_default: i32,
    pub dns_udp53_excluded: bool,
    pub live_endpoint_created: bool,
}

pub const fn active_tcp_topology_contract() -> ActiveTcpTopologyContract {
    ActiveTcpTopologyContract {
        client_netns: ACTIVE_TCP_CLIENT_NETNS,
        lan_host_iface: ACTIVE_TCP_LAN_HOST_IFACE,
        lan_client_iface: ACTIVE_TCP_LAN_CLIENT_IFACE,
        lan_gateway_ip: ACTIVE_TCP_LAN_GATEWAY_IP,
        lan_filter_pref: ACTIVE_TCP_LAN_FILTER_PREF,
        lan_section: ACTIVE_TCP_LAN_SECTION,
    }
}

pub const fn active_tcp_routing_map_contract(mark: u32) -> ActiveTcpRoutingMapContract {
    ActiveTcpRoutingMapContract {
        map_name: ACTIVE_TCP_ROUTING_MAP_KERNEL_NAME,
        key_size: ACTIVE_TCP_ROUTING_MAP_KEY_SIZE,
        value_size: ACTIVE_TCP_ROUTING_MAP_VALUE_SIZE,
        key: ACTIVE_TCP_ROUTING_MAP_KEY,
        match_type: ACTIVE_TCP_MATCH_TYPE_FALLBACK,
        outbound: ACTIVE_TCP_OUTBOUND_PROXY,
        mark,
        must: false,
    }
}

pub fn active_tcp_routing_fallback_value(contract: &ActiveTcpRoutingMapContract) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[17] = contract.match_type;
    value[18] = contract.outbound;
    value[20..24].copy_from_slice(&contract.mark.to_ne_bytes());
    value
}

pub const fn active_udp_endpoint_contract() -> ActiveUdpEndpointContract {
    ActiveUdpEndpointContract {
        key_model: "client-source-full-cone",
        nat_timeout_ms: super::udp_endpoint::DEFAULT_NAT_TIMEOUT_MS,
        dns_nat_timeout_ms: super::udp_endpoint::DNS_NAT_TIMEOUT_MS,
        anyfrom_timeout_ms: super::udp_endpoint::ANYFROM_TIMEOUT_MS,
        max_retry: super::udp_endpoint::MAX_RETRY,
        pool_max_entries_default: super::udp_endpoint::DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        dns_udp53_excluded: true,
        live_endpoint_created: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_TCP_DEFAULT_MPTCP, ACTIVE_TCP_DEFAULT_SO_MARK, ACTIVE_TCP_MATCH_TYPE_FALLBACK,
        ACTIVE_TCP_OUTBOUND_PROXY, ACTIVE_UDP_DEFAULT_TARGET_PORT,
        active_tcp_routing_fallback_value, active_tcp_routing_map_contract,
        active_tcp_topology_contract, active_udp_endpoint_contract,
    };
    use crate::{DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES, DNS_NAT_TIMEOUT_MS};

    #[test]
    fn active_tcp_contract_preserves_topology_and_routing_map_layout() {
        let topology = active_tcp_topology_contract();
        assert_eq!(topology.client_netns, "dae50client");
        assert_eq!(topology.lan_host_iface, "dae50lan0");
        assert_eq!(topology.lan_client_iface, "dae50cli0");
        assert_eq!(topology.lan_gateway_ip, "10.220.50.1");

        let routing = active_tcp_routing_map_contract(ACTIVE_TCP_DEFAULT_SO_MARK);
        assert_eq!(routing.map_name, "routing_map");
        assert_eq!(routing.key_size, 4);
        assert_eq!(routing.value_size, 24);
        assert_eq!(routing.match_type, ACTIVE_TCP_MATCH_TYPE_FALLBACK);
        assert_eq!(routing.outbound, ACTIVE_TCP_OUTBOUND_PROXY);
        assert!(!routing.must);
        assert!(ACTIVE_TCP_DEFAULT_MPTCP);

        let value = active_tcp_routing_fallback_value(&routing);
        assert_eq!(value[17], ACTIVE_TCP_MATCH_TYPE_FALLBACK);
        assert_eq!(value[18], ACTIVE_TCP_OUTBOUND_PROXY);
        assert_eq!(&value[20..24], &ACTIVE_TCP_DEFAULT_SO_MARK.to_ne_bytes());
    }

    #[test]
    fn active_udp_contract_preserves_endpoint_pool_rules() {
        let contract = active_udp_endpoint_contract();
        assert_eq!(ACTIVE_UDP_DEFAULT_TARGET_PORT, 18083);
        assert_eq!(contract.key_model, "client-source-full-cone");
        assert_eq!(contract.dns_nat_timeout_ms, DNS_NAT_TIMEOUT_MS);
        assert_eq!(
            contract.pool_max_entries_default,
            DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES
        );
        assert!(contract.dns_udp53_excluded);
        assert!(!contract.live_endpoint_created);
    }
}
