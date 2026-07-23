use std::net::IpAddr;
use std::sync::Arc;

use super::IpPrefix;

// The permanent routing benchmarks compare the retained linear path at 32
// entries with the indexed crossover at 64 entries for IPv4 and IPv6. Keep
// this policy tied to those cases rather than a deployment-specific rule set.
const PREFIX_INDEX_MIN_PREFIXES: usize = 64;

#[derive(Clone, Debug)]
pub(super) enum IpPrefixLookup {
    Linear,
    Indexed(Arc<IpRangeIndex>),
}

impl IpPrefixLookup {
    pub(super) fn for_prefixes(prefixes: &[IpPrefix]) -> Self {
        if prefixes.len() < PREFIX_INDEX_MIN_PREFIXES {
            return Self::Linear;
        }
        Self::Indexed(Arc::new(IpRangeIndex::new(prefixes)))
    }

    pub(super) fn contains(&self, prefixes: &[IpPrefix], addr: IpAddr) -> bool {
        match self {
            Self::Linear => prefixes.iter().any(|prefix| prefix.contains(addr)),
            Self::Indexed(index) => index.contains(addr),
        }
    }

    #[cfg(test)]
    fn is_indexed(&self) -> bool {
        matches!(self, Self::Indexed(_))
    }
}

#[derive(Clone, Debug)]
pub(super) struct IpRangeIndex {
    ipv4: Vec<PrefixRange<u32>>,
    ipv6: Vec<PrefixRange<u128>>,
}

impl IpRangeIndex {
    fn new(prefixes: &[IpPrefix]) -> Self {
        let ipv4_count = prefixes
            .iter()
            .filter(|prefix| prefix.addr().is_ipv4())
            .count();
        let mut ipv4 = Vec::with_capacity(ipv4_count);
        let mut ipv6 = Vec::with_capacity(prefixes.len() - ipv4_count);
        for prefix in prefixes {
            match prefix.addr() {
                IpAddr::V4(addr) => {
                    let mask = prefix_mask_u32(prefix.bits());
                    let start = u32::from(addr) & mask;
                    ipv4.push(PrefixRange {
                        start,
                        end: start | !mask,
                    });
                }
                IpAddr::V6(addr) => {
                    let mask = prefix_mask_u128(prefix.bits());
                    let start = u128::from(addr) & mask;
                    ipv6.push(PrefixRange {
                        start,
                        end: start | !mask,
                    });
                }
            }
        }
        Self {
            ipv4: merge_ranges(ipv4),
            ipv6: merge_ranges(ipv6),
        }
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => range_contains(&self.ipv4, u32::from(addr)),
            IpAddr::V6(addr) => range_contains(&self.ipv6, u128::from(addr)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PrefixRange<T> {
    start: T,
    end: T,
}

trait RangeValue: Copy + Ord {
    fn next_saturating(self) -> Self;
}

impl RangeValue for u32 {
    fn next_saturating(self) -> Self {
        self.saturating_add(1)
    }
}

impl RangeValue for u128 {
    fn next_saturating(self) -> Self {
        self.saturating_add(1)
    }
}

fn merge_ranges<T: RangeValue>(mut ranges: Vec<PrefixRange<T>>) -> Vec<PrefixRange<T>> {
    ranges.sort_unstable_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
    });
    if ranges.is_empty() {
        return ranges;
    }
    let mut merged_end = 0;
    for current in 1..ranges.len() {
        let range = ranges[current];
        let previous = &mut ranges[merged_end];
        if range.start <= previous.end.next_saturating() {
            previous.end = previous.end.max(range.end);
        } else {
            merged_end += 1;
            ranges[merged_end] = range;
        }
    }
    ranges.truncate(merged_end + 1);
    ranges
}

fn range_contains<T: Copy + Ord>(ranges: &[PrefixRange<T>], value: T) -> bool {
    let insertion = ranges.partition_point(|range| range.start <= value);
    insertion > 0 && value <= ranges[insertion - 1].end
}

fn prefix_mask_u32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (u32::BITS - u32::from(bits))
    }
}

fn prefix_mask_u128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (u128::BITS - u32::from(bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn lookup_policy_keeps_small_sets_linear_and_indexes_large_sets() {
        let small = prefix_sequence(63);
        let large = prefix_sequence(64);

        assert!(!IpPrefixLookup::for_prefixes(&small).is_indexed());
        assert!(IpPrefixLookup::for_prefixes(&large).is_indexed());
    }

    #[test]
    fn indexed_lookup_matches_linear_reference_for_both_families() {
        let mut prefixes = prefix_sequence(256);
        prefixes.extend([
            IpPrefix::parse("10.1.2.3/8").unwrap(),
            IpPrefix::parse("2001:db8:1:2::1/48").unwrap(),
            IpPrefix::parse("2001:db8:ffff::/64").unwrap(),
        ]);
        let lookup = IpPrefixLookup::for_prefixes(&prefixes);
        assert!(lookup.is_indexed());

        let mut state = 0x67d5_6cda_91e1_0da5_u64;
        for _ in 0..4096 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let ipv4 = IpAddr::V4(Ipv4Addr::from(state as u32));
            assert_eq!(
                lookup.contains(&prefixes, ipv4),
                prefixes.iter().any(|prefix| prefix.contains(ipv4))
            );

            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let raw = (u128::from(state) << 64) | u128::from(state.rotate_left(29));
            let ipv6 = IpAddr::V6(Ipv6Addr::from(raw));
            assert_eq!(
                lookup.contains(&prefixes, ipv6),
                prefixes.iter().any(|prefix| prefix.contains(ipv6))
            );
        }
    }

    #[test]
    fn indexed_lookup_merges_duplicate_overlapping_and_adjacent_ranges() {
        let mut prefixes = prefix_sequence(64);
        prefixes.extend([
            IpPrefix::parse("192.0.2.1/24").unwrap(),
            IpPrefix::parse("192.0.2.0/25").unwrap(),
            IpPrefix::parse("192.0.3.0/24").unwrap(),
            IpPrefix::parse("2001:db8::/127").unwrap(),
            IpPrefix::parse("2001:db8::2/127").unwrap(),
        ]);
        let IpPrefixLookup::Indexed(index) = IpPrefixLookup::for_prefixes(&prefixes) else {
            panic!("expected indexed lookup");
        };

        assert!(index.contains("192.0.2.255".parse().unwrap()));
        assert!(index.contains("192.0.3.255".parse().unwrap()));
        assert!(!index.contains("192.0.4.0".parse().unwrap()));
        assert!(index.contains("2001:db8::3".parse().unwrap()));
        assert!(!index.contains("2001:db8::4".parse().unwrap()));
    }

    #[test]
    fn indexed_lookup_handles_zero_length_prefixes_by_family() {
        let mut ipv4 = prefix_sequence(64);
        ipv4.push(IpPrefix::parse("203.0.113.42/0").unwrap());
        let ipv4_lookup = IpPrefixLookup::for_prefixes(&ipv4);
        assert!(ipv4_lookup.contains(&ipv4, "192.0.2.1".parse().unwrap()));
        assert!(!ipv4_lookup.contains(&ipv4, "2001:db8::1".parse().unwrap()));

        let mut ipv6 = prefix_sequence(64);
        ipv6.push(IpPrefix::parse("2001:db8::1/0").unwrap());
        let ipv6_lookup = IpPrefixLookup::for_prefixes(&ipv6);
        assert!(ipv6_lookup.contains(&ipv6, "2001:db8:ffff::1".parse().unwrap()));
        assert!(!ipv6_lookup.contains(&ipv6, "192.0.2.1".parse().unwrap()));
    }

    fn prefix_sequence(count: usize) -> Vec<IpPrefix> {
        (0..count)
            .map(|index| {
                let addr = Ipv4Addr::from(0x0a00_0000_u32.wrapping_add(index as u32 * 257));
                IpPrefix::new(IpAddr::V4(addr), 32).unwrap()
            })
            .collect()
    }
}
