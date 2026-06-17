use super::*;
impl DomainRoutingOwnerSnapshot {
    pub fn new(bitmap_words: &[u32], ips: &[&str]) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            bitmap,
            ips: normalize_ip_keys(ips.iter().filter_map(|ip| parse_ip_key(ip))),
        }
    }

    pub fn from_keys(bitmap_words: &[u32], ips: &[DomainRoutingIpKey]) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            bitmap,
            ips: normalize_ip_keys(ips.iter().copied()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.bitmap.iter().all(|word| *word == 0)
    }
}
