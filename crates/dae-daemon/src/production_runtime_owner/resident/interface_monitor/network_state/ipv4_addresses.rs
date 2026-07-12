use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use super::{InterfaceAddressFingerprint, NetworkFamily};

pub(super) fn ipv4_interface_addresses(
    wanted_ifaces: &BTreeSet<String>,
) -> io::Result<BTreeMap<String, Vec<InterfaceAddressFingerprint>>> {
    let mut head = std::ptr::null_mut::<libc::ifaddrs>();
    // SAFETY: getifaddrs initializes `head` on success. The returned list remains
    // valid until the matching freeifaddrs call owned by `IfAddrsGuard`.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = IfAddrsGuard(head);
    let mut addresses = BTreeMap::<String, Vec<InterfaceAddressFingerprint>>::new();
    let mut current = guard.0;
    while !current.is_null() {
        // SAFETY: every non-null node belongs to the live getifaddrs list. We
        // only advance through ifa_next while `guard` keeps that list alive.
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
            // SAFETY: getifaddrs guarantees that a non-null ifa_name points to a
            // NUL-terminated interface name for the lifetime of the list.
            let iface = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: the pointer is non-null above and reading sa_family does
            // not outlive the guarded getifaddrs allocation.
            let is_ipv4 = unsafe { (*entry.ifa_addr).sa_family as libc::c_int } == libc::AF_INET;
            // SAFETY: `ipv4_from_sockaddr` verifies AF_INET before casting.
            let address = unsafe { ipv4_from_sockaddr(entry.ifa_addr) };
            if wanted_ifaces.contains(&iface)
                && is_ipv4
                && let Some(address) = address
                && !address.is_unspecified()
                && !address.is_loopback()
            {
                // SAFETY: null and non-IPv4 netmask pointers are handled by the
                // helper, and any valid pointer is owned by the guarded list.
                let prefix_len = unsafe { ipv4_from_sockaddr(entry.ifa_netmask) }
                    .map(ipv4_prefix_len)
                    .unwrap_or_default();
                let peer = if entry.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0 {
                    // SAFETY: Linux exposes the point-to-point destination in
                    // ifa_ifu; the helper validates its address family.
                    unsafe { ipv4_from_sockaddr(entry.ifa_ifu) }.map(IpAddr::V4)
                } else {
                    None
                };
                addresses
                    .entry(iface)
                    .or_default()
                    .push(InterfaceAddressFingerprint {
                        family: NetworkFamily::Ipv4,
                        address: IpAddr::V4(address),
                        prefix_len,
                        peer,
                        scope: 0,
                    });
            }
        }
        current = entry.ifa_next;
    }
    Ok(addresses)
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer came from the successful getifaddrs call and
            // this guard is its sole owner, so it is freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

unsafe fn ipv4_from_sockaddr(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if address.is_null()
        // SAFETY: null was excluded, and the pointer belongs to the live
        // getifaddrs list for this entire call.
        || unsafe { (*address).sa_family as libc::c_int } != libc::AF_INET
    {
        return None;
    }
    // SAFETY: AF_INET sockaddr values returned by getifaddrs have the layout of
    // sockaddr_in and sufficient alignment for this cast.
    let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
    Some(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
}

fn ipv4_prefix_len(mask: Ipv4Addr) -> u8 {
    u32::from_be_bytes(mask.octets()).count_ones() as u8
}
