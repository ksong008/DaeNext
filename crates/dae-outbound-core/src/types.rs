use dae_core_types::NetworkTypeId;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

impl L4Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

pub const NETWORK_TYPE_COLLECTION_COUNT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }

    pub fn fallback(self) -> Self {
        match self {
            Self::V4 => Self::V6,
            Self::V6 => Self::V4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkType {
    pub l4proto: L4Proto,
    pub ipversion: IpVersion,
    pub is_dns: bool,
}

impl NetworkType {
    pub const DNS_TCP4: Self = Self {
        l4proto: L4Proto::Tcp,
        ipversion: IpVersion::V4,
        is_dns: true,
    };
    pub const DNS_TCP6: Self = Self {
        l4proto: L4Proto::Tcp,
        ipversion: IpVersion::V6,
        is_dns: true,
    };
    pub const DNS_UDP4: Self = Self {
        l4proto: L4Proto::Udp,
        ipversion: IpVersion::V4,
        is_dns: true,
    };
    pub const DNS_UDP6: Self = Self {
        l4proto: L4Proto::Udp,
        ipversion: IpVersion::V6,
        is_dns: true,
    };
    pub const DATA_UDP4: Self = Self {
        l4proto: L4Proto::Udp,
        ipversion: IpVersion::V4,
        is_dns: false,
    };
    pub const DATA_UDP6: Self = Self {
        l4proto: L4Proto::Udp,
        ipversion: IpVersion::V6,
        is_dns: false,
    };
    pub const TCP4: Self = Self {
        l4proto: L4Proto::Tcp,
        ipversion: IpVersion::V4,
        is_dns: false,
    };
    pub const TCP6: Self = Self {
        l4proto: L4Proto::Tcp,
        ipversion: IpVersion::V6,
        is_dns: false,
    };

    pub fn collection_index(self) -> usize {
        match (self.is_dns, self.l4proto, self.ipversion) {
            (true, L4Proto::Tcp, IpVersion::V4) => 0,
            (true, L4Proto::Tcp, IpVersion::V6) => 1,
            (true, L4Proto::Udp, IpVersion::V4) => 2,
            (true, L4Proto::Udp, IpVersion::V6) => 3,
            (false, L4Proto::Tcp, IpVersion::V4) => 4,
            (false, L4Proto::Tcp, IpVersion::V6) => 5,
            (false, L4Proto::Udp, IpVersion::V4) => 6,
            (false, L4Proto::Udp, IpVersion::V6) => 7,
        }
    }

    pub fn is_data_udp(self) -> bool {
        self.l4proto == L4Proto::Udp && !self.is_dns
    }

    pub fn dns_udp_for_ipversion(ipversion: IpVersion) -> Self {
        Self {
            l4proto: L4Proto::Udp,
            ipversion,
            is_dns: true,
        }
    }

    pub fn tcp_for_ipversion(ipversion: IpVersion) -> Self {
        Self {
            l4proto: L4Proto::Tcp,
            ipversion,
            is_dns: false,
        }
    }

    pub fn with_ipversion(self, ipversion: IpVersion) -> Self {
        Self { ipversion, ..self }
    }

    pub fn string_without_dns(self) -> String {
        self.label_without_dns().to_owned()
    }

    pub fn label_without_dns(self) -> &'static str {
        match (self.l4proto, self.ipversion) {
            (L4Proto::Tcp, IpVersion::V4) => "tcp4",
            (L4Proto::Tcp, IpVersion::V6) => "tcp6",
            (L4Proto::Udp, IpVersion::V4) => "udp4",
            (L4Proto::Udp, IpVersion::V6) => "udp6",
        }
    }

    pub fn dimension_name(self) -> &'static str {
        match (self.is_dns, self.l4proto, self.ipversion) {
            (true, L4Proto::Tcp, IpVersion::V4) => "dns-tcp4",
            (true, L4Proto::Tcp, IpVersion::V6) => "dns-tcp6",
            (true, L4Proto::Udp, IpVersion::V4) => "dns-udp4",
            (true, L4Proto::Udp, IpVersion::V6) => "dns-udp6",
            (false, L4Proto::Tcp, IpVersion::V4) => "tcp4",
            (false, L4Proto::Tcp, IpVersion::V6) => "tcp6",
            (false, L4Proto::Udp, IpVersion::V4) => "data-udp4",
            (false, L4Proto::Udp, IpVersion::V6) => "data-udp6",
        }
    }

    pub fn from_dimension_name(value: &str) -> Option<Self> {
        [
            Self::DNS_TCP4,
            Self::DNS_TCP6,
            Self::DNS_UDP4,
            Self::DNS_UDP6,
            Self::TCP4,
            Self::TCP6,
            Self::DATA_UDP4,
            Self::DATA_UDP6,
        ]
        .into_iter()
        .find(|network_type| network_type.dimension_name() == value)
    }
}

impl From<NetworkType> for NetworkTypeId {
    fn from(network_type: NetworkType) -> Self {
        match network_type.collection_index() {
            0 => Self::DnsTcp4,
            1 => Self::DnsTcp6,
            2 => Self::DnsUdp4,
            3 => Self::DnsUdp6,
            4 => Self::Tcp4,
            5 => Self::Tcp6,
            6 => Self::DataUdp4,
            7 => Self::DataUdp6,
            _ => unreachable!("network type collection index is bounded"),
        }
    }
}

impl From<NetworkTypeId> for NetworkType {
    fn from(network_type: NetworkTypeId) -> Self {
        match network_type {
            NetworkTypeId::DnsTcp4 => Self::DNS_TCP4,
            NetworkTypeId::DnsTcp6 => Self::DNS_TCP6,
            NetworkTypeId::DnsUdp4 => Self::DNS_UDP4,
            NetworkTypeId::DnsUdp6 => Self::DNS_UDP6,
            NetworkTypeId::Tcp4 => Self::TCP4,
            NetworkTypeId::Tcp6 => Self::TCP6,
            NetworkTypeId::DataUdp4 => Self::DATA_UDP4,
            NetworkTypeId::DataUdp6 => Self::DATA_UDP6,
        }
    }
}
