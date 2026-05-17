use crate::error::OutboundError;

use super::address::Socks5Address;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5UdpDatagram {
    pub reserved: [u8; 2],
    pub fragment: u8,
    pub target: Socks5Address,
    pub payload: Vec<u8>,
}

pub fn wrap(target: &Socks5Address, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 0]);
    target.write_to(&mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn wrap_target(target: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    wrap(&Socks5Address::parse(target)?, payload)
}

pub fn unwrap(input: &[u8]) -> Result<Socks5UdpDatagram, OutboundError> {
    if input.len() < 4 {
        return Err(OutboundError::BadSocks5Packet(
            "udp packet too short".to_owned(),
        ));
    }
    let (target, consumed) = Socks5Address::decode(&input[3..])?;
    Ok(Socks5UdpDatagram {
        reserved: [input[0], input[1]],
        fragment: input[2],
        target,
        payload: input[3 + consumed..].to_vec(),
    })
}
