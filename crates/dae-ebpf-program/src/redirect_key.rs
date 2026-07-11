use core::ptr;

use crate::abi::{
    BpfRedirectKey, BpfTuplesKey, REDIRECT_TRACK_ABI_VERSION, param_redirect_generation,
};
use crate::packet;

#[inline(always)]
pub unsafe fn from_forward_tuple(tuple: *const BpfTuplesKey, key: *mut BpfRedirectKey) {
    unsafe {
        ptr::write(
            key,
            BpfRedirectKey {
                sip: (*tuple).sip,
                dip: (*tuple).dip,
                sport: (*tuple).sport,
                dport: (*tuple).dport,
                l4proto: (*tuple).l4proto,
                abi_version: REDIRECT_TRACK_ABI_VERSION,
                padding: [0; 2],
                generation: param_redirect_generation(),
            },
        );
    }
}

#[inline(always)]
pub unsafe fn from_return_tuple(tuple: *const BpfTuplesKey, key: *mut BpfRedirectKey) {
    let mut forward = BpfTuplesKey::zeroed();
    unsafe {
        packet::reverse_tuples(tuple, ptr::addr_of_mut!(forward));
        from_forward_tuple(ptr::addr_of!(forward), key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::BpfIpBytes;

    fn ip(last: u8) -> BpfIpBytes {
        let mut value = BpfIpBytes::zeroed();
        value.u6_addr8[15] = last;
        value
    }

    fn tuple(sport: u16, dport: u16, l4proto: u8) -> BpfTuplesKey {
        BpfTuplesKey {
            sip: ip(1),
            dip: ip(2),
            sport,
            dport,
            l4proto,
            padding: [0; 3],
        }
    }

    #[test]
    fn forward_and_return_tuples_rebuild_the_same_flow_key() {
        let forward = tuple(12345, 443, 6);
        let mut reverse = BpfTuplesKey::zeroed();
        let mut forward_key = BpfRedirectKey::zeroed();
        let mut return_key = BpfRedirectKey::zeroed();
        unsafe {
            packet::reverse_tuples(&forward, &mut reverse);
            from_forward_tuple(&forward, &mut forward_key);
            from_return_tuple(&reverse, &mut return_key);
        }
        assert_eq!(forward_key.sip.u6_addr8, return_key.sip.u6_addr8);
        assert_eq!(forward_key.dip.u6_addr8, return_key.dip.u6_addr8);
        assert_eq!(forward_key.sport, return_key.sport);
        assert_eq!(forward_key.dport, return_key.dport);
        assert_eq!(forward_key.l4proto, return_key.l4proto);
        assert_eq!(forward_key.abi_version, REDIRECT_TRACK_ABI_VERSION);
        assert_eq!(forward_key.generation, return_key.generation);
    }

    #[test]
    fn ports_and_protocol_are_part_of_redirect_identity() {
        let mut first = BpfRedirectKey::zeroed();
        let mut second = BpfRedirectKey::zeroed();
        let mut third = BpfRedirectKey::zeroed();
        unsafe {
            from_forward_tuple(&tuple(10000, 443, 6), &mut first);
            from_forward_tuple(&tuple(10001, 443, 6), &mut second);
            from_forward_tuple(&tuple(10000, 443, 17), &mut third);
        }
        assert_ne!(first.sport, second.sport);
        assert_ne!(first.l4proto, third.l4proto);
    }
}
