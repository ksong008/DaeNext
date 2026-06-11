pub fn magic_network(network: &str, mark: u32, mptcp: bool) -> String {
    String::from_utf8(magic_network_bytes(network, mark, mptcp)).expect("magic network is UTF-8")
}

pub fn magic_network_bytes(network: &str, mark: u32, mptcp: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(magic_network_len(network, mark, mptcp));
    write_magic_network_bytes(network, mark, mptcp, &mut bytes);
    bytes
}

pub fn write_magic_network_bytes(network: &str, mark: u32, mptcp: bool, out: &mut Vec<u8>) {
    if mark == 0 && !mptcp {
        out.extend_from_slice(network.as_bytes());
        return;
    }
    assert!(network.len() <= u8::MAX as usize, "network too long");
    out.push(0);
    out.push(network.len() as u8);
    out.extend_from_slice(network.as_bytes());
    out.extend_from_slice(&mark.to_be_bytes());
    out.push(u8::from(mptcp));
}

pub fn magic_network_len(network: &str, mark: u32, mptcp: bool) -> usize {
    if mark == 0 && !mptcp {
        network.len()
    } else {
        2 + network.len() + 4 + 1
    }
}
