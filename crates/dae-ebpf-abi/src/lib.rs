#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDaeParam {
    pub tproxy_port: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub has_bpf_get_current_task: u8,
    pub tproxy_port_protect: u8,
    pub task_struct_mm_offset: u32,
    pub mm_struct_arg_start_offset: u32,
    pub abi_version: u32,
    pub udp_state_saturation_policy: u32,
    pub udp_state_idle_timeout_ns: u64,
}

impl BpfDaeParam {
    pub const fn zeroed() -> Self {
        Self {
            tproxy_port: 0,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0; 6],
            has_bpf_get_current_task: 0,
            tproxy_port_protect: 0,
            task_struct_mm_offset: 0,
            mm_struct_arg_start_offset: 0,
            abi_version: 0,
            udp_state_saturation_policy: UDP_STATE_SATURATION_POLICY_FAIL_CLOSED,
            udp_state_idle_timeout_ns: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfIpBytes {
    pub u6_addr8: [u8; 16],
}

impl BpfIpBytes {
    pub const fn zeroed() -> Self {
        Self { u6_addr8: [0; 16] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDomainRouting {
    pub bitmap: [u32; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfMatchSet {
    pub value: [u8; 16],
    pub not: u8,
    pub kind: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct BpfOutboundConnectivityQuery {
    pub outbound: u8,
    pub l4proto: u8,
    pub ipversion: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfPidPname {
    pub pid: u32,
    pub comm: [i8; TASK_COMM_LEN],
    pub pname: [i8; TASK_COMM_LEN],
}

impl BpfPidPname {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            comm: [0; TASK_COMM_LEN],
            pname: [0; TASK_COMM_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRedirectEntry {
    pub ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub from_wan: u8,
    pub link_layer: u8,
    pub abi_version: u8,
    pub vlan_metadata: u8,
    pub vlan_tci: [u16; 2],
}

impl BpfRedirectEntry {
    pub const fn zeroed() -> Self {
        Self {
            ifindex: 0,
            smac: [0; 6],
            dmac: [0; 6],
            from_wan: 0,
            link_layer: 0,
            abi_version: 0,
            vlan_metadata: 0,
            vlan_tci: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRedirectKey {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub abi_version: u8,
    pub padding: [u8; 2],
    pub generation: u64,
}

impl BpfRedirectKey {
    pub const fn zeroed() -> Self {
        Self {
            sip: BpfIpBytes::zeroed(),
            dip: BpfIpBytes::zeroed(),
            sport: 0,
            dport: 0,
            l4proto: 0,
            abi_version: 0,
            padding: [0; 2],
            generation: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; TASK_COMM_LEN],
    pub pid: u32,
    pub dscp: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfTuplesKey {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

impl BpfTuplesKey {
    pub const fn zeroed() -> Self {
        Self {
            sip: BpfIpBytes::zeroed(),
            dip: BpfIpBytes::zeroed(),
            sport: 0,
            dport: 0,
            l4proto: 0,
            padding: [0; 3],
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct bpf_timer {
    pub __opaque: [u64; 2],
}

pub type BpfTimerOpaque = bpf_timer;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfUdpConnState {
    pub is_wan_ingress_direction: u8,
    pub padding: [u8; 7],
    pub timer: bpf_timer,
}

impl BpfUdpConnState {
    pub const fn new(is_wan_ingress_direction: bool) -> Self {
        Self {
            is_wan_ingress_direction: is_wan_ingress_direction as u8,
            padding: [0; 7],
            timer: bpf_timer { __opaque: [0; 2] },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfUdpStateMetrics {
    pub state_created_total: u64,
    pub state_refresh_total: u64,
    pub insert_failure_total: u64,
    pub post_insert_lookup_failure_total: u64,
    pub timer_init_failure_total: u64,
    pub timer_callback_failure_total: u64,
    pub timer_start_failure_total: u64,
}

/// Per-CPU counters for transparent-proxy datapath failures that were
/// previously unobservable (their helper return values were discarded).
/// Kept as its own map (not folded into `BpfUdpStateMetrics`) because the
/// two metric families measure unrelated subsystems: this one is the tproxy
/// redirect path, the other is the UDP connection-state lifecycle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfTproxyMetrics {
    /// `bpf_sk_assign` failed in `assign_listener`: the packet keeps the
    /// tproxy mark but no listener socket is assigned, so it is not
    /// redirected into the dae listener (a redirect hole).
    pub sk_assign_failure_total: u64,
    /// `bpf_skb_store_bytes` failed while preparing the packet for
    /// redirect-to-control-plane (l3proto ethertype on L3 devices, or the
    /// dae0peer MAC rewrite). The packet is dropped fail-closed.
    pub redirect_prep_store_failure_total: u64,
    /// `bpf_skb_store_bytes` failed while restoring the original MACs on the
    /// dae0 ingress return path. The packet is dropped fail-closed.
    pub redirect_restore_store_failure_total: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfLpmKey {
    pub prefix_len: u32,
    pub data: [u32; 4],
}

impl BpfLpmKey {
    pub const fn zeroed() -> Self {
        Self {
            prefix_len: 0,
            data: [0; 4],
        }
    }

    pub const fn from_ipv4_mapped(prefix_bits: u8, address: [u8; 4]) -> Self {
        assert!(prefix_bits <= 32, "IPv4 LPM prefix exceeds 32 bits");
        let mut octets = [0_u8; 16];
        octets[10] = 0xff;
        octets[11] = 0xff;
        octets[12] = address[0];
        octets[13] = address[1];
        octets[14] = address[2];
        octets[15] = address[3];
        Self::from_octets(BPF_LPM_IPV4_MAPPED_PREFIX_BITS + prefix_bits as u32, octets)
    }

    pub const fn from_ipv6(prefix_bits: u8, address: [u8; 16]) -> Self {
        assert!(prefix_bits <= 128, "IPv6 LPM prefix exceeds 128 bits");
        Self::from_octets(prefix_bits as u32, address)
    }

    pub const fn from_mac(address: [u8; 6]) -> Self {
        let mut octets = [0_u8; 16];
        let mut index = 0;
        while index < address.len() {
            octets[BPF_LPM_MAC_OFFSET + index] = address[index];
            index += 1;
        }
        Self::from_octets(BPF_LPM_FULL_PREFIX_BITS, octets)
    }

    pub const fn octets(self) -> [u8; 16] {
        let words = self.data;
        let first = words[0].to_ne_bytes();
        let second = words[1].to_ne_bytes();
        let third = words[2].to_ne_bytes();
        let fourth = words[3].to_ne_bytes();
        [
            first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
            third[0], third[1], third[2], third[3], fourth[0], fourth[1], fourth[2], fourth[3],
        ]
    }

    const fn from_octets(prefix_len: u32, octets: [u8; 16]) -> Self {
        Self {
            prefix_len,
            data: [
                u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
                u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
                u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
                u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
            ],
        }
    }
}

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_MATCH_SET_LEN: u32 = 32 * 32;
pub const MATCH_TYPE_DOMAIN_SET: u8 = 0;
pub const MATCH_TYPE_IP_SET: u8 = 1;
pub const MATCH_TYPE_SOURCE_IP_SET: u8 = 2;
pub const MATCH_TYPE_PORT: u8 = 3;
pub const MATCH_TYPE_SOURCE_PORT: u8 = 4;
pub const MATCH_TYPE_L4_PROTO: u8 = 5;
pub const MATCH_TYPE_IP_VERSION: u8 = 6;
pub const MATCH_TYPE_MAC: u8 = 7;
pub const MATCH_TYPE_PROCESS_NAME: u8 = 8;
pub const MATCH_TYPE_DSCP: u8 = 9;
pub const MATCH_TYPE_FALLBACK: u8 = 10;
pub const BPF_LPM_IPV4_MAPPED_PREFIX_BITS: u32 = 96;
pub const BPF_LPM_FULL_PREFIX_BITS: u32 = 128;
pub const BPF_LPM_MAC_OFFSET: usize = 10;
pub const TPROXY_MARK: u32 = 0x0800_0000;
pub const BPF_DAE_PARAM_ABI_VERSION: u32 = 2;
pub const UDP_STATE_SATURATION_POLICY_FAIL_CLOSED: u32 = 0;
pub const UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT: u64 = 300_000_000_000;
pub const REDIRECT_TRACK_ABI_VERSION: u8 = 3;

#[cfg(test)]
mod lpm_contract_tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn lpm_key_layout_is_stable() {
        assert_eq!(size_of::<BpfLpmKey>(), 20);
        assert_eq!(align_of::<BpfLpmKey>(), 4);
        assert_eq!(offset_of!(BpfLpmKey, prefix_len), 0);
        assert_eq!(offset_of!(BpfLpmKey, data), 4);
    }

    #[test]
    fn lpm_key_constructors_preserve_kernel_lookup_bytes() {
        let ipv4 = BpfLpmKey::from_ipv4_mapped(24, [192, 0, 2, 1]);
        assert_eq!(ipv4.prefix_len, 120);
        assert_eq!(
            ipv4.octets(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]
        );

        let ipv6_address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ipv6 = BpfLpmKey::from_ipv6(64, ipv6_address);
        assert_eq!(ipv6.prefix_len, 64);
        assert_eq!(ipv6.octets(), ipv6_address);

        let mac = BpfLpmKey::from_mac([0x02, 0, 0, 0, 0, 1]);
        assert_eq!(mac.prefix_len, BPF_LPM_FULL_PREFIX_BITS);
        assert_eq!(
            mac.octets(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn routing_match_kinds_remain_wire_stable() {
        assert_eq!(
            [
                MATCH_TYPE_DOMAIN_SET,
                MATCH_TYPE_IP_SET,
                MATCH_TYPE_SOURCE_IP_SET,
                MATCH_TYPE_PORT,
                MATCH_TYPE_SOURCE_PORT,
                MATCH_TYPE_L4_PROTO,
                MATCH_TYPE_IP_VERSION,
                MATCH_TYPE_MAC,
                MATCH_TYPE_PROCESS_NAME,
                MATCH_TYPE_DSCP,
                MATCH_TYPE_FALLBACK,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
    }
}
pub const LINK_HDR_LEN_NONE: u32 = 0;
pub const LINK_HDR_LEN_ETHERNET: u32 = 14;

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for BpfDaeParam {}

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for BpfUdpStateMetrics {}

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for BpfTproxyMetrics {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn shared_abi_layout_is_stable() {
        assert_eq!(size_of::<BpfDaeParam>(), 48);
        assert_eq!(align_of::<BpfDaeParam>(), 8);
        assert_eq!(offset_of!(BpfDaeParam, tproxy_port_protect), 23);
        assert_eq!(offset_of!(BpfDaeParam, abi_version), 32);
        assert_eq!(size_of::<BpfMatchSet>(), 24);
        assert_eq!(size_of::<BpfRedirectEntry>(), 24);
        assert_eq!(size_of::<BpfRedirectKey>(), 48);
        assert_eq!(size_of::<BpfRoutingResult>(), 36);
        assert_eq!(size_of::<BpfTuplesKey>(), 40);
        assert_eq!(
            core::any::type_name::<BpfTimerOpaque>(),
            "dae_ebpf_abi::bpf_timer"
        );
        assert_eq!(size_of::<BpfTimerOpaque>(), 16);
        assert_eq!(align_of::<BpfTimerOpaque>(), 8);
        assert_eq!(size_of::<BpfUdpConnState>(), 24);
        assert_eq!(offset_of!(BpfUdpConnState, timer), 8);
        assert_eq!(size_of::<BpfTproxyMetrics>(), 24);
        assert_eq!(align_of::<BpfTproxyMetrics>(), 8);
    }
}
