mod boring_mlkem;
mod kdf;
mod stream;

pub use stream::VlessEncryptedStream;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::OutboundError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessEncryptionMode {
    Native,
    XorPublicKey,
    Random,
}

impl VlessEncryptionMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "native" => Some(Self::Native),
            "xorpub" => Some(Self::XorPublicKey),
            "random" => Some(Self::Random),
            _ => None,
        }
    }

    fn xor_public_key(self) -> bool {
        !matches!(self, Self::Native)
    }

    fn random_records(self) -> bool {
        matches!(self, Self::Random)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessEncryptionRtt {
    OneRtt,
    ZeroRtt,
}

impl VlessEncryptionRtt {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "1rtt" => Some(Self::OneRtt),
            "0rtt" => Some(Self::ZeroRtt),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PaddingPart {
    probability: u8,
    from: usize,
    to: usize,
}

impl PaddingPart {
    fn parse(raw: &str, first: bool) -> Result<Self, OutboundError> {
        let fields = raw.split('-').collect::<Vec<_>>();
        if fields.len() < 3 || fields[..3].iter().any(|field| field.is_empty()) {
            return Err(OutboundError::BadVless(format!(
                "invalid VLESS Encryption padding rule: {raw}"
            )));
        }
        let probability = fields[0].parse::<u16>().map_err(|_| {
            OutboundError::BadVless(format!(
                "invalid VLESS Encryption padding probability: {raw}"
            ))
        })?;
        let from = fields[1].parse::<usize>().map_err(|_| {
            OutboundError::BadVless(format!(
                "invalid VLESS Encryption padding lower bound: {raw}"
            ))
        })?;
        let to = fields[2].parse::<usize>().map_err(|_| {
            OutboundError::BadVless(format!(
                "invalid VLESS Encryption padding upper bound: {raw}"
            ))
        })?;
        if probability > 100 || from > to {
            return Err(OutboundError::BadVless(format!(
                "invalid VLESS Encryption padding range: {raw}"
            )));
        }
        if first && (probability != 100 || from < 35 || to < 35) {
            return Err(OutboundError::BadVless(
                "first VLESS Encryption padding rule must reserve at least 35 bytes".to_owned(),
            ));
        }
        Ok(Self {
            probability: probability as u8,
            from,
            to,
        })
    }

    fn sample(&self) -> usize {
        if fastrand::u8(0..100) >= self.probability {
            return 0;
        }
        if self.from == self.to {
            self.from
        } else {
            fastrand::usize(self.from..self.to)
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PaddingPlan {
    lengths: Vec<PaddingPart>,
    gaps: Vec<PaddingPart>,
}

impl PaddingPlan {
    fn parse(raw: &str) -> Result<Self, OutboundError> {
        if raw.is_empty() {
            return Ok(Self::default());
        }
        let mut lengths = Vec::new();
        let mut gaps = Vec::new();
        let mut max_total = 0usize;
        for (index, field) in raw.split('.').enumerate() {
            let part = PaddingPart::parse(field, index == 0)?;
            if index % 2 == 0 {
                max_total = max_total.saturating_add(part.to);
                lengths.push(part);
            } else {
                gaps.push(part);
            }
        }
        if lengths.is_empty() || max_total > 65_553 {
            return Err(OutboundError::BadVless(
                "VLESS Encryption padding total is outside the Xray contract".to_owned(),
            ));
        }
        Ok(Self { lengths, gaps })
    }

    fn sample(&self) -> (Vec<usize>, Vec<std::time::Duration>) {
        let default_lengths = [
            PaddingPart {
                probability: 100,
                from: 111,
                to: 1111,
            },
            PaddingPart {
                probability: 50,
                from: 0,
                to: 3333,
            },
        ];
        let default_gaps = [PaddingPart {
            probability: 75,
            from: 0,
            to: 111,
        }];
        let lengths = if self.lengths.is_empty() {
            default_lengths.as_slice()
        } else {
            self.lengths.as_slice()
        };
        let gaps = if self.gaps.is_empty() {
            default_gaps.as_slice()
        } else {
            self.gaps.as_slice()
        };
        (
            lengths.iter().map(PaddingPart::sample).collect(),
            gaps.iter()
                .map(|part| std::time::Duration::from_millis(part.sample() as u64))
                .collect(),
        )
    }

    fn encoded_fragment_lengths(&self) -> (Vec<usize>, Vec<std::time::Duration>) {
        self.sample()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VlessEncryptionSpec {
    mode: VlessEncryptionMode,
    rtt: VlessEncryptionRtt,
    public_keys: Vec<Vec<u8>>,
    padding: PaddingPlan,
}

impl VlessEncryptionSpec {
    fn parse(raw: &str) -> Result<Option<Self>, OutboundError> {
        if raw.is_empty() || raw == "none" {
            return Ok(None);
        }
        let fields = raw.split('.').collect::<Vec<_>>();
        if fields.len() < 4 || fields[0] != "mlkem768x25519plus" {
            return Err(OutboundError::BadVless(format!(
                "unsupported VLESS encryption: {raw}"
            )));
        }
        let mode = VlessEncryptionMode::parse(fields[1]).ok_or_else(|| {
            OutboundError::BadVless(format!("unsupported VLESS Encryption mode: {}", fields[1]))
        })?;
        let rtt = VlessEncryptionRtt::parse(fields[2]).ok_or_else(|| {
            OutboundError::BadVless(format!(
                "unsupported VLESS Encryption RTT mode: {}",
                fields[2]
            ))
        })?;
        let mut padding_fields = Vec::new();
        let mut public_keys = Vec::new();
        for field in &fields[3..] {
            if field.len() < 20 {
                padding_fields.push(*field);
                continue;
            }
            let decoded = URL_SAFE_NO_PAD.decode(field).map_err(|_| {
                OutboundError::BadVless("VLESS Encryption key is not base64url".to_owned())
            })?;
            if decoded.len() != 32 && decoded.len() != 1184 {
                return Err(OutboundError::BadVless(format!(
                    "VLESS Encryption client key must be 32 or 1184 bytes, got {}",
                    decoded.len()
                )));
            }
            public_keys.push(decoded);
        }
        if public_keys.is_empty() {
            return Err(OutboundError::BadVless(
                "VLESS Encryption requires at least one X25519 or ML-KEM-768 client key".to_owned(),
            ));
        }
        let padding = PaddingPlan::parse(&padding_fields.join("."))?;
        Ok(Some(Self {
            mode,
            rtt,
            public_keys,
            padding,
        }))
    }
}

#[derive(Clone)]
pub struct VlessEncryptionClient {
    pub(crate) spec: Arc<VlessEncryptionSpec>,
    pub(crate) ticket: Arc<Mutex<Option<VlessEncryptionTicket>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct VlessEncryptionTicket {
    pub(crate) expires_at: std::time::Instant,
    pub(crate) pfs_key: [u8; 64],
    pub(crate) ticket: [u8; 16],
}

impl Drop for VlessEncryptionTicket {
    fn drop(&mut self) {
        unsafe {
            boring_sys::OPENSSL_cleanse(self.pfs_key.as_mut_ptr().cast(), self.pfs_key.len());
            boring_sys::OPENSSL_cleanse(self.ticket.as_mut_ptr().cast(), self.ticket.len());
        }
    }
}

impl fmt::Debug for VlessEncryptionClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessEncryptionClient")
            .field("mode", &self.spec.mode)
            .field("rtt", &self.spec.rtt)
            .field("key_count", &self.spec.public_keys.len())
            .finish()
    }
}

impl PartialEq for VlessEncryptionClient {
    fn eq(&self, other: &Self) -> bool {
        self.spec == other.spec
    }
}

impl Eq for VlessEncryptionClient {}

impl VlessEncryptionClient {
    pub fn parse(raw: &str) -> Result<Option<Self>, OutboundError> {
        let Some(spec) = VlessEncryptionSpec::parse(raw)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            spec: Arc::new(spec),
            ticket: Arc::new(Mutex::new(None)),
        }))
    }

    pub fn mode(&self) -> VlessEncryptionMode {
        self.spec.mode
    }

    pub fn rtt(&self) -> VlessEncryptionRtt {
        self.spec.rtt
    }
}
