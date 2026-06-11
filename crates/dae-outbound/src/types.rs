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
            (false, L4Proto::Udp, IpVersion::V4) => 2,
            (false, L4Proto::Udp, IpVersion::V6) => 3,
        }
    }

    pub fn with_ipversion(self, ipversion: IpVersion) -> Self {
        Self { ipversion, ..self }
    }

    pub fn string_without_dns(self) -> String {
        format!("{}{}", self.l4proto.as_str(), self.ipversion.as_str())
    }
}
