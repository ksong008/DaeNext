use dae_netutil::{MagicNetworkEncoding, magic_network_encoded_len, write_magic_network_to_vec};

pub fn magic_network(network: &str, mark: u32, mptcp: bool) -> String {
    String::from_utf8(magic_network_bytes(network, mark, mptcp)).expect("magic network is UTF-8")
}

pub fn magic_network_bytes(network: &str, mark: u32, mptcp: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(magic_network_len(network, mark, mptcp));
    write_magic_network_bytes(network, mark, mptcp, &mut bytes);
    bytes
}

pub fn write_magic_network_bytes(network: &str, mark: u32, mptcp: bool, out: &mut Vec<u8>) {
    write_magic_network_to_vec(
        network,
        mark,
        mptcp,
        MagicNetworkEncoding::PlainWhenEligible,
        out,
    )
    .expect("network too long");
}

pub fn magic_network_len(network: &str, mark: u32, mptcp: bool) -> usize {
    magic_network_encoded_len(
        network,
        mark,
        mptcp,
        MagicNetworkEncoding::PlainWhenEligible,
    )
    .expect("network too long")
}
