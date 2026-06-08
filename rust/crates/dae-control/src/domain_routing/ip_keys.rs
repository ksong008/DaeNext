use super::*;
pub(super) fn normalize_ip_keys(
    keys: impl IntoIterator<Item = DomainRoutingIpKey>,
) -> Vec<DomainRoutingIpKey> {
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub fn parse_ip_key(ip: &str) -> Option<DomainRoutingIpKey> {
    let ip = ip.parse::<IpAddr>().ok()?;
    Some(ip_to_key(ip))
}

pub fn ip_to_key(ip: IpAddr) -> DomainRoutingIpKey {
    let octets = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    [
        u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}

pub fn format_ip_key(key: &DomainRoutingIpKey) -> String {
    let mut octets = [0_u8; 16];
    for (index, word) in key.iter().enumerate() {
        octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        return Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]).to_string();
    }
    Ipv6Addr::from(octets).to_string()
}

pub(super) fn trimmed_bitmap(bitmap: &[u32; 32]) -> Vec<u32> {
    let mut end = bitmap.len();
    while end > 0 && bitmap[end - 1] == 0 {
        end -= 1;
    }
    bitmap[..end].to_vec()
}
