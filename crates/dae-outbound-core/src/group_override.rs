use std::collections::HashMap;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HealthProfile {
    pub tcp_check_url_key: String,
    pub tcp_check_http_method: String,
    pub tcp_check_resolver_network: String,
    pub tcp_check_resolver_identity: String,
    pub tcp_check_resolver_dns: String,
    pub udp_check_dns_key: String,
    pub udp_check_resolver_network: String,
    pub udp_check_resolver_identity: String,
    pub udp_check_somark: u32,
    pub udp_check_resolver_dns: String,
    pub check_interval_ms: i64,
    pub check_tolerance_ms: i64,
    pub check_dns_tcp: bool,
}

impl HealthProfile {
    pub fn new(tcp_check_url: Option<&[String]>, udp_check_dns: Option<&[String]>) -> Self {
        Self {
            tcp_check_url_key: string_slice_profile_key(tcp_check_url),
            tcp_check_http_method: "HEAD".to_owned(),
            tcp_check_resolver_network: "udp".to_owned(),
            tcp_check_resolver_identity: "resolver-a".to_owned(),
            tcp_check_resolver_dns: "1.1.1.1:53".to_owned(),
            udp_check_dns_key: string_slice_profile_key(udp_check_dns),
            udp_check_resolver_network: "udp".to_owned(),
            udp_check_resolver_identity: "resolver-a".to_owned(),
            udp_check_somark: 123,
            udp_check_resolver_dns: "1.1.1.1:53".to_owned(),
            check_interval_ms: 15_000,
            check_tolerance_ms: 10,
            check_dns_tcp: true,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CloneKey {
    base_id: usize,
    profile: HealthProfile,
}

#[derive(Clone, Debug, Default)]
pub struct GroupOverrideCloneCache {
    next_clone_id: usize,
    dialers: HashMap<CloneKey, usize>,
}

impl GroupOverrideCloneCache {
    pub fn clone_id(&mut self, base_id: usize, profile: HealthProfile) -> usize {
        let key = CloneKey { base_id, profile };
        if let Some(id) = self.dialers.get(&key) {
            return *id;
        }
        self.next_clone_id += 1;
        let id = self.next_clone_id;
        self.dialers.insert(key, id);
        id
    }

    pub fn created_count(&self) -> usize {
        self.next_clone_id
    }
}

pub fn string_slice_profile_key(values: Option<&[String]>) -> String {
    let Some(values) = values else {
        return "nil".to_owned();
    };
    let mut out = format!("{}|", values.len());
    for value in values {
        out.push_str(&value.len().to_string());
        out.push(':');
        out.push_str(value);
        out.push('|');
    }
    out
}
