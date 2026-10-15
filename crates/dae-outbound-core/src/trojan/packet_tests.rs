use super::*;
use crate::socks5::Socks5Address;

#[test]
fn typed_udp_packets_preserve_wire_format_and_reuse_capacity() {
    let mut scratch = Vec::with_capacity(65568);
    let allocation = scratch.as_ptr();
    for target in ["192.0.2.1:53", "[2001:db8::1]:443", "example.com:53"] {
        let address = Socks5Address::parse(target).unwrap();
        let expected = [
            address.encode().unwrap().as_slice(),
            &[0, 3],
            b"\r\n",
            b"udp",
        ]
        .concat();
        udp_packet_into(&address, b"udp", &mut scratch).unwrap();
        assert_eq!(scratch, expected);
        assert_eq!(udp_packet(target, b"udp").unwrap(), expected);
        assert_eq!(scratch.as_ptr(), allocation);
    }
    let scoped: std::net::SocketAddr = "[fe80::1%3]:53".parse().unwrap();
    assert!(matches!(
        Socks5Address::from(scoped),
        Socks5Address::Ipv6 { .. }
    ));
    let address = Socks5Address::from(scoped);
    udp_packet_into(&address, &vec![7; 65535], &mut scratch).unwrap();
    assert_eq!(scratch.as_ptr(), allocation);
    assert!(udp_packet_into(&address, &vec![0; 65536], &mut scratch).is_err());
}
