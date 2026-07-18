use std::collections::BTreeMap;

use md5::{Digest, Md5};

use crate::error::OutboundError;

use super::contract;

const MAX_RECORD_TARGET_BYTES: u64 = u16::MAX as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsPaddingScheme {
    raw: Vec<u8>,
    md5_hex: String,
    stop: u32,
    records: BTreeMap<u32, Vec<AnyTlsPaddingRecordSize>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnyTlsPaddingRecordSize {
    Target { minimum: u16, maximum: u16 },
    Check,
}

impl AnyTlsPaddingScheme {
    pub fn parse(raw: &[u8]) -> Result<Self, OutboundError> {
        let text = std::str::from_utf8(raw).map_err(|_| {
            OutboundError::BadAnyTLS("AnyTLS padding scheme is not UTF-8".to_owned())
        })?;
        let fields = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        if fields.is_empty() {
            return Err(OutboundError::BadAnyTLS(
                "AnyTLS padding scheme is empty".to_owned(),
            ));
        }
        let stop = fields
            .get("stop")
            .ok_or_else(|| {
                OutboundError::BadAnyTLS("AnyTLS padding scheme has no stop value".to_owned())
            })?
            .parse::<u32>()
            .map_err(|_| {
                OutboundError::BadAnyTLS("AnyTLS padding scheme stop value is invalid".to_owned())
            })?;
        let mut records = BTreeMap::new();
        for (packet, value) in fields {
            let Ok(packet) = packet.parse::<u32>() else {
                continue;
            };
            let mut sizes = Vec::new();
            for raw_size in value.split(',') {
                if raw_size == "c" {
                    sizes.push(AnyTlsPaddingRecordSize::Check);
                    continue;
                }
                let Some((minimum, maximum)) = raw_size.split_once('-') else {
                    continue;
                };
                let (Ok(mut minimum), Ok(mut maximum)) =
                    (minimum.parse::<u64>(), maximum.parse::<u64>())
                else {
                    continue;
                };
                if minimum == 0 || maximum == 0 {
                    continue;
                }
                if minimum > maximum {
                    std::mem::swap(&mut minimum, &mut maximum);
                }
                minimum = minimum.min(MAX_RECORD_TARGET_BYTES);
                maximum = maximum.min(MAX_RECORD_TARGET_BYTES);
                sizes.push(AnyTlsPaddingRecordSize::Target {
                    minimum: minimum as u16,
                    maximum: maximum as u16,
                });
            }
            records.insert(packet, sizes);
        }
        Ok(Self {
            raw: raw.to_vec(),
            md5_hex: md5_hex(raw),
            stop,
            records,
        })
    }

    pub fn official_default() -> Self {
        Self::parse(contract::DEFAULT_PADDING_RAW.as_bytes())
            .expect("the built-in AnyTLS padding scheme is valid")
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn md5_hex(&self) -> &str {
        &self.md5_hex
    }

    pub fn settings_bytes(&self) -> Vec<u8> {
        format!("v=2\nclient=dae\npadding-md5={}", self.md5_hex).into_bytes()
    }

    pub fn sample_record_payload_sizes(&self, packet: u32, output: &mut Vec<i32>) {
        output.clear();
        let Some(records) = self.records.get(&packet) else {
            return;
        };
        output.reserve(records.len());
        for record in records {
            match *record {
                AnyTlsPaddingRecordSize::Check => output.push(contract::CHECK_MARK),
                AnyTlsPaddingRecordSize::Target { minimum, maximum } => {
                    output.push(i32::from(sample_half_open(minimum, maximum)));
                }
            }
        }
    }
}

impl Default for AnyTlsPaddingScheme {
    fn default() -> Self {
        Self::official_default()
    }
}

fn sample_half_open(minimum: u16, maximum: u16) -> u16 {
    if minimum >= maximum {
        return minimum;
    }
    let span = u64::from(maximum - minimum);
    let unbiased_limit = u64::MAX - (u64::MAX % span);
    loop {
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            return minimum;
        }
        let sample = u64::from_ne_bytes(bytes);
        if sample < unbiased_limit {
            return minimum + (sample % span) as u16;
        }
    }
}

fn md5_hex(raw: &[u8]) -> String {
    Md5::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_the_advertised_contract_and_half_open_ranges() {
        let scheme = AnyTlsPaddingScheme::official_default();
        assert_eq!(scheme.stop(), contract::PADDING_STOP);
        assert_eq!(scheme.md5_hex(), contract::DEFAULT_PADDING_MD5);
        assert_eq!(scheme.raw(), contract::DEFAULT_PADDING_RAW.as_bytes());
        assert_eq!(
            scheme.settings_bytes(),
            super::super::link::settings_bytes()
        );

        let mut sizes = Vec::new();
        for _ in 0..128 {
            scheme.sample_record_payload_sizes(1, &mut sizes);
            assert_eq!(sizes.len(), 1);
            assert!((100..400).contains(&sizes[0]));
        }
        scheme.sample_record_payload_sizes(2, &mut sizes);
        assert_eq!(sizes.len(), 9);
        assert_eq!(sizes[1], contract::CHECK_MARK);
    }

    #[test]
    fn updated_scheme_is_bounded_by_the_wire_record_limit() {
        let scheme = AnyTlsPaddingScheme::parse(b"stop=2\n1=999999-999999,c").unwrap();
        let mut sizes = Vec::new();
        scheme.sample_record_payload_sizes(1, &mut sizes);
        assert_eq!(sizes, vec![i32::from(u16::MAX), contract::CHECK_MARK]);
        assert!(AnyTlsPaddingScheme::parse(b"1=10-20").is_err());
        assert!(AnyTlsPaddingScheme::parse(b"stop=x\n1=10-20").is_err());
    }
}
