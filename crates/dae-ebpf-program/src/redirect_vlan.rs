use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::__sk_buff;

use crate::abi::BpfRedirectEntry;
use crate::helpers;
use crate::packet::{self, ParsedPacket, VLAN_DEPTH_MASK};

const MAX_VLAN_DEPTH: u8 = 2;
const VLAN_HEADER_LEN: i32 = 4;
const BPF_ADJ_ROOM_MAC: u32 = 1;
const ETH_PROTOCOL_OFFSET: u32 = 12;
const OUTER_TCI_OFFSET: u32 = 14;
const INNER_PROTOCOL_OFFSET: u32 = 16;
const INNER_TCI_OFFSET: u32 = 18;
const SINGLE_INNER_PROTOCOL_OFFSET: u32 = 16;
const DOUBLE_INNER_PROTOCOL_OFFSET: u32 = 20;

#[inline(always)]
unsafe fn store_u16(skb: *mut __sk_buff, offset: u32, value: u16) -> bool {
    unsafe {
        helpers::bpf_skb_store_bytes(
            skb.cast::<c_void>(),
            offset,
            ptr::addr_of!(value).cast::<c_void>(),
            2,
            0,
        ) == 0
    }
}

#[inline(always)]
pub unsafe fn capture(info: *const ParsedPacket, entry: *mut BpfRedirectEntry) -> bool {
    let metadata = unsafe { (*info).vlan_metadata };
    if metadata & VLAN_DEPTH_MASK > MAX_VLAN_DEPTH {
        return false;
    }
    unsafe {
        ptr::addr_of_mut!((*entry).vlan_metadata).write(metadata);
        ptr::addr_of_mut!((*entry).vlan_tci).write((*info).vlan_tci);
    }
    true
}

#[inline(always)]
pub unsafe fn strip(skb: *mut __sk_buff, info: *const ParsedPacket) -> bool {
    let depth = unsafe { (*info).vlan_metadata } & VLAN_DEPTH_MASK;
    if depth > MAX_VLAN_DEPTH {
        return false;
    }
    if depth >= 1 && unsafe { helpers::bpf_skb_vlan_pop(skb.cast::<c_void>()) } != 0 {
        return false;
    }
    if depth >= 2 && unsafe { helpers::bpf_skb_vlan_pop(skb.cast::<c_void>()) } != 0 {
        return false;
    }
    true
}

#[inline(always)]
pub unsafe fn restore(
    skb: *mut __sk_buff,
    entry: *const BpfRedirectEntry,
    l3_protocol: u16,
) -> bool {
    let metadata = unsafe { (*entry).vlan_metadata };
    let depth = metadata & VLAN_DEPTH_MASK;
    if depth > MAX_VLAN_DEPTH {
        return false;
    }

    if depth == 0 {
        return true;
    }
    if unsafe {
        helpers::bpf_skb_adjust_room(
            skb.cast::<c_void>(),
            VLAN_HEADER_LEN * depth as i32,
            BPF_ADJ_ROOM_MAC,
            0,
        )
    } != 0
    {
        return false;
    }

    let outer_protocol = packet::vlan_protocol_at(metadata, 0);
    let outer_tci = unsafe { (*entry).vlan_tci[0] }.to_be();
    if !unsafe { store_u16(skb, ETH_PROTOCOL_OFFSET, outer_protocol) }
        || !unsafe { store_u16(skb, OUTER_TCI_OFFSET, outer_tci) }
    {
        return false;
    }
    if depth == 1 {
        return unsafe { store_u16(skb, SINGLE_INNER_PROTOCOL_OFFSET, l3_protocol) };
    }

    let inner_protocol = packet::vlan_protocol_at(metadata, 1);
    let inner_tci = unsafe { (*entry).vlan_tci[1] }.to_be();
    unsafe {
        store_u16(skb, INNER_PROTOCOL_OFFSET, inner_protocol)
            && store_u16(skb, INNER_TCI_OFFSET, inner_tci)
            && store_u16(skb, DOUBLE_INNER_PROTOCOL_OFFSET, l3_protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_preserves_depth_and_tag_protocols() {
        let metadata = 2 | 0b0000_0100;
        assert_eq!(metadata & VLAN_DEPTH_MASK, 2);
        assert_eq!(
            packet::vlan_protocol_at(metadata, 0),
            packet::ETH_P_8021AD_NETWORK as u16
        );
        assert_eq!(
            packet::vlan_protocol_at(metadata, 1),
            packet::ETH_P_8021Q_NETWORK as u16
        );
    }

    #[test]
    fn captured_tci_values_fit_the_compact_redirect_entry() {
        let mut packet = ParsedPacket::zeroed();
        packet.vlan_metadata = 2 | 0b0000_0100;
        packet.vlan_tci = [200, 100];
        let mut entry = BpfRedirectEntry::zeroed();
        assert!(unsafe { capture(&packet, &mut entry) });
        assert_eq!(entry.vlan_metadata & VLAN_DEPTH_MASK, 2);
        assert_eq!(entry.vlan_tci, [200, 100]);
    }
}
