use super::*;
impl<'a> DomainRoutingDnsEvent<'a> {
    pub fn from_keys(
        owner_key: &'a str,
        bitmap_words: &[u32],
        ips: impl IntoIterator<Item = DomainRoutingIpKey>,
    ) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            owner_key,
            bitmap,
            ips: normalize_ip_keys(ips),
        }
    }

    pub fn remove(owner_key: &'a str) -> Self {
        Self {
            owner_key,
            bitmap: [0; 32],
            ips: Vec::new(),
        }
    }

    pub fn into_snapshot(self) -> DomainRoutingOwnerSnapshot {
        DomainRoutingOwnerSnapshot {
            bitmap: self.bitmap,
            ips: self.ips,
        }
    }
}
