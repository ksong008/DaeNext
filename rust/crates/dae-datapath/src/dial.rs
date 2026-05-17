pub fn magic_network(network: &str, mark: u32, mptcp: bool) -> String {
    String::from_utf8(magic_network_bytes(network, mark, mptcp)).expect("magic network is UTF-8")
}

pub fn magic_network_bytes(network: &str, mark: u32, mptcp: bool) -> Vec<u8> {
    if mark == 0 && !mptcp {
        return network.as_bytes().to_vec();
    }
    assert!(network.len() <= u8::MAX as usize, "network too long");
    let mut bytes = Vec::with_capacity(2 + network.len() + 4 + 1);
    bytes.push(0);
    bytes.push(network.len() as u8);
    bytes.extend_from_slice(network.as_bytes());
    bytes.extend_from_slice(&mark.to_be_bytes());
    bytes.push(u8::from(mptcp));
    bytes
}
