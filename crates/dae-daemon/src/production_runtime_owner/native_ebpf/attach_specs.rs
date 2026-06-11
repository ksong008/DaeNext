#[cfg(feature = "native-ebpf")]
use super::*;
#[cfg(feature = "native-ebpf")]
pub(super) fn native_attach_spec(
    role: NativeEbpfAttachRole,
    param_object: &Path,
) -> TcNativeAttachSpec {
    let object = path_string(param_object);
    match role {
        NativeEbpfAttachRole::PeerIngress => TcBpfAttachSpec::new(
            TcAttachTarget::netns(
                PRODUCTION_NETNS,
                PRODUCTION_PEER_IFACE,
                TcAttachDirection::Ingress,
            ),
            FILTER_PREF,
            object,
            "classifier/dae0peer_ingress",
        )
        .native_attach_spec("tproxy_dae0peer_ingress", 0, tc_handle(0x2022, 0b010)),
        NativeEbpfAttachRole::LanIngress => TcBpfAttachSpec::new(
            TcAttachTarget::host(ACTIVE_TCP_LAN_HOST_IFACE, TcAttachDirection::Ingress),
            ACTIVE_TCP_LAN_FILTER_PREF,
            object,
            "classifier/lan_ingress_l2",
        )
        .native_attach_spec("tproxy_lan_ingress_l2", 2, tc_handle(0x2023, 0b100)),
        NativeEbpfAttachRole::HostIngress => TcBpfAttachSpec::new(
            TcAttachTarget::host(PRODUCTION_HOST_IFACE, TcAttachDirection::Ingress),
            FILTER_PREF,
            object,
            "classifier/dae0_ingress",
        )
        .native_attach_spec("tproxy_dae0_ingress", 0, tc_handle(0x2022, 0b010)),
    }
}
