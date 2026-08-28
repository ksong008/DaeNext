use std::fmt;

pub const L4_PROTO_TCP: &str = "tcp";
pub const L4_PROTO_UDP: &str = "udp";
pub const IP_VERSION_4: &str = "4";
pub const IP_VERSION_6: &str = "6";
pub const DNS_NAT_TIMEOUT_MS: i64 = 17_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkTypeId {
    DnsTcp4,
    DnsTcp6,
    DnsUdp4,
    DnsUdp6,
    Tcp4,
    Tcp6,
    DataUdp4,
    DataUdp6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L4ProtoStr {
    Tcp,
    Udp,
}

impl L4ProtoStr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => L4_PROTO_TCP,
            Self::Udp => L4_PROTO_UDP,
        }
    }

    pub const fn to_l4_proto_type(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }
}

impl fmt::Display for L4ProtoStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersionStr {
    V4,
    V6,
}

impl IpVersionStr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => IP_VERSION_4,
            Self::V6 => IP_VERSION_6,
        }
    }

    pub const fn to_ip_version(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

impl fmt::Display for IpVersionStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_dimensions_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/dial_mode_policy.json").unwrap();
        let dimensions = &fixture["network_dimensions"];

        assert_eq!(
            L4ProtoStr::Tcp.to_string(),
            dimensions["l4_proto"]["tcp"].as_str().unwrap()
        );
        assert_eq!(
            L4ProtoStr::Udp.to_string(),
            dimensions["l4_proto"]["udp"].as_str().unwrap()
        );
        assert_eq!(
            IpVersionStr::V4.to_string(),
            dimensions["ip_version"]["ipv4"].as_str().unwrap()
        );
        assert_eq!(
            IpVersionStr::V6.to_string(),
            dimensions["ip_version"]["ipv6"].as_str().unwrap()
        );
    }
}
