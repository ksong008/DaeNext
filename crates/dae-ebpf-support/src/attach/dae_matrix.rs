use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeTcAttachRole {
    LanIngress,
    LanEgress,
    WanIngress,
    WanEgress,
    Dae0peerIngress,
    Dae0Ingress,
}

impl DaeTcAttachRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LanIngress => "lan_ingress",
            Self::LanEgress => "lan_egress",
            Self::WanIngress => "wan_ingress",
            Self::WanEgress => "wan_egress",
            Self::Dae0peerIngress => "dae0peer_ingress",
            Self::Dae0Ingress => "dae0_ingress",
        }
    }

    pub(super) const fn has_link_layer_variant(self) -> bool {
        matches!(
            self,
            Self::LanIngress | Self::LanEgress | Self::WanIngress | Self::WanEgress
        )
    }

    pub(super) const fn direction(self) -> TcAttachDirection {
        match self {
            Self::LanIngress | Self::WanIngress | Self::Dae0peerIngress | Self::Dae0Ingress => {
                TcAttachDirection::Ingress
            }
            Self::LanEgress | Self::WanEgress => TcAttachDirection::Egress,
        }
    }

    pub(super) const fn priority(self) -> u16 {
        match self {
            Self::LanIngress | Self::WanEgress => 2,
            Self::LanEgress | Self::WanIngress => 1,
            Self::Dae0peerIngress | Self::Dae0Ingress => 0,
        }
    }

    pub(super) const fn handle_major(self) -> u16 {
        match self {
            Self::LanIngress | Self::LanEgress | Self::WanIngress | Self::WanEgress => {
                IFACE_TC_HANDLE_MAJOR
            }
            Self::Dae0peerIngress | Self::Dae0Ingress => DAE_TC_HANDLE_MAJOR,
        }
    }

    pub(super) const fn handle_minor_base(self) -> u16 {
        match self {
            Self::LanIngress | Self::WanEgress => 0b100,
            Self::LanEgress | Self::WanIngress | Self::Dae0peerIngress | Self::Dae0Ingress => 0b010,
        }
    }

    pub(super) fn source_uses_flipped_cleanup_on_fresh_start(self) -> bool {
        // The peer cleanup branch deletes the original dae0peer filter.
        self != Self::Dae0peerIngress
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeTcAttachMatrixInput {
    pub object: String,
    pub lan_iface: String,
    pub wan_iface: String,
    pub host_iface: String,
    pub peer_iface: String,
    pub peer_netns: String,
    pub section_prefix: TcAttachSectionPrefix,
    pub link_layer: TcAttachLayer,
    pub flip: u16,
    pub is_reload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeTcAttachLine {
    pub role: DaeTcAttachRole,
    pub filter_name: String,
    pub attach: TcBpfAttachSpec,
    pub native: TcNativeAttachSpec,
    pub stale_cleanup_handle_on_fresh_start: Option<u32>,
}

pub fn dae_tc_attach_matrix(input: DaeTcAttachMatrixInput) -> Vec<DaeTcAttachLine> {
    [
        DaeTcAttachRole::LanIngress,
        DaeTcAttachRole::LanEgress,
        DaeTcAttachRole::WanIngress,
        DaeTcAttachRole::WanEgress,
        DaeTcAttachRole::Dae0peerIngress,
        DaeTcAttachRole::Dae0Ingress,
    ]
    .into_iter()
    .map(|role| dae_tc_attach_line(&input, role))
    .collect()
}

pub(super) fn dae_tc_attach_line(
    input: &DaeTcAttachMatrixInput,
    role: DaeTcAttachRole,
) -> DaeTcAttachLine {
    let target = match role {
        DaeTcAttachRole::LanIngress | DaeTcAttachRole::LanEgress => {
            TcAttachTarget::host(input.lan_iface.clone(), role.direction())
        }
        DaeTcAttachRole::WanIngress | DaeTcAttachRole::WanEgress => {
            TcAttachTarget::host(input.wan_iface.clone(), role.direction())
        }
        DaeTcAttachRole::Dae0Ingress => {
            TcAttachTarget::host(input.host_iface.clone(), role.direction())
        }
        DaeTcAttachRole::Dae0peerIngress => TcAttachTarget::netns(
            input.peer_netns.clone(),
            input.peer_iface.clone(),
            role.direction(),
        ),
    };
    let suffix = if role.has_link_layer_variant() {
        format!("_{}", input.link_layer.suffix())
    } else {
        String::new()
    };
    let section_name = format!("{}{}", role.as_str(), suffix);
    let section = format!("{}/{}", input.section_prefix.as_str(), section_name);
    let program_name = format!("tproxy_{section_name}");
    let filter_name = format!("dae_{section_name}");
    let attach = TcBpfAttachSpec::new(
        target,
        role.priority().to_string(),
        input.object.clone(),
        section,
    );
    let handle_minor = role.handle_minor_base() + (input.flip & 1);
    let native = attach.native_attach_spec(
        program_name,
        role.priority(),
        tc_handle(role.handle_major(), handle_minor),
    );
    let stale_cleanup_handle_on_fresh_start =
        if input.is_reload || !role.source_uses_flipped_cleanup_on_fresh_start() {
            None
        } else {
            Some(native.handle ^ 1)
        };
    DaeTcAttachLine {
        role,
        filter_name,
        attach,
        native,
        stale_cleanup_handle_on_fresh_start,
    }
}
