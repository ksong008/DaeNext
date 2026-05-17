use crate::error::OutboundError;

use super::address::Socks5Address;

pub const VERSION: u8 = 5;
pub const AUTH_NONE: u8 = 0;
pub const AUTH_PASSWORD: u8 = 2;
pub const AUTH_NO_ACCEPTABLE_METHODS: u8 = 0xff;
pub const PASSWORD_AUTH_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Socks5Command {
    Connect,
    UdpAssociate,
}

impl Socks5Command {
    pub fn byte(self) -> u8 {
        match self {
            Self::Connect => 1,
            Self::UdpAssociate => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerReply {
    pub reply: u8,
    pub bind: Socks5Address,
    pub bytes_read: usize,
}

pub fn greeting(username: &str, password: &str) -> Vec<u8> {
    if password_auth_allowed(username, password) {
        vec![VERSION, 2, AUTH_NONE, AUTH_PASSWORD]
    } else {
        vec![VERSION, 1, AUTH_NONE]
    }
}

pub fn password_auth_allowed(username: &str, password: &str) -> bool {
    !username.is_empty() && username.len() < 256 && password.len() < 256
}

pub fn username_password_auth(username: &str, password: &str) -> Result<Vec<u8>, OutboundError> {
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(OutboundError::BadSocks5Auth(
            "username/password too long".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(3 + username.len() + password.len());
    out.push(PASSWORD_AUTH_VERSION);
    out.push(username.len() as u8);
    out.extend_from_slice(username.as_bytes());
    out.push(password.len() as u8);
    out.extend_from_slice(password.as_bytes());
    Ok(out)
}

pub fn request(command: Socks5Command, target: &Socks5Address) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::new();
    out.push(VERSION);
    out.push(command.byte());
    out.push(0);
    target.write_to(&mut out)?;
    Ok(out)
}

pub fn connect_request(target: &str) -> Result<Vec<u8>, OutboundError> {
    request(Socks5Command::Connect, &Socks5Address::parse(target)?)
}

pub fn udp_associate_request(target: &str) -> Result<Vec<u8>, OutboundError> {
    request(Socks5Command::UdpAssociate, &Socks5Address::parse(target)?)
}

pub fn parse_method_selection(input: &[u8]) -> Result<u8, OutboundError> {
    if input.len() != 2 {
        return Err(OutboundError::BadSocks5Reply(format!(
            "method selection length: {}",
            input.len()
        )));
    }
    if input[0] != VERSION {
        return Err(OutboundError::BadSocks5Reply(format!(
            "unexpected version: {}",
            input[0]
        )));
    }
    if input[1] == AUTH_NO_ACCEPTABLE_METHODS {
        return Err(OutboundError::BadSocks5Reply(
            "proxy requires unsupported authentication".to_owned(),
        ));
    }
    Ok(input[1])
}

pub fn parse_server_reply(input: &[u8]) -> Result<ServerReply, OutboundError> {
    if input.len() < 4 {
        return Err(OutboundError::BadSocks5Reply(
            "server reply too short".to_owned(),
        ));
    }
    if input[0] != VERSION {
        return Err(OutboundError::BadSocks5Reply(format!(
            "unexpected version: {}",
            input[0]
        )));
    }
    if input[2] != 0 {
        return Err(OutboundError::BadSocks5Reply(format!(
            "unexpected reserved byte: {}",
            input[2]
        )));
    }
    if input[1] != 0 {
        return Err(OutboundError::BadSocks5Reply(format!(
            "server failure reply: {}",
            input[1]
        )));
    }
    let (bind, consumed) = Socks5Address::decode(&input[3..])?;
    Ok(ServerReply {
        reply: input[1],
        bind,
        bytes_read: 3 + consumed,
    })
}
