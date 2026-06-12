use std::net::{Ipv4Addr, Ipv6Addr};

use crate::GeoDataError;
use crate::wire::{
    decode_entry_bytes, entries_from_list, read_length_delimited, read_varint, skip_field, string,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoIp {
    pub country_code: String,
    pub cidrs: Vec<String>,
    pub inverse_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoSite {
    pub country_code: String,
    pub domains: Vec<Domain>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub domain_type: DomainType,
    pub value: String,
    pub attributes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainType {
    Plain,
    Regex,
    RootDomain,
    Full,
}

impl DomainType {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Plain => "Plain",
            Self::Regex => "Regex",
            Self::RootDomain => "RootDomain",
            Self::Full => "Full",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadResult<T> {
    pub decode_ok: bool,
    pub fallback_ok: bool,
    pub decoded_entry_bytes: usize,
    pub value: T,
}

pub fn load_geoip_bytes(data: &[u8], code: &str) -> Result<LoadResult<GeoIp>, GeoDataError> {
    match decode_entry_bytes(data, code) {
        Ok(entry) => load_geoip_entry_bytes(&entry),
        Err(err) if err.is_full_read_fallback_candidate() => {
            let (value, decoded_entry_bytes) = find_geoip_from_list(data, code)?;
            Ok(LoadResult {
                decode_ok: false,
                fallback_ok: true,
                decoded_entry_bytes,
                value,
            })
        }
        Err(GeoDataError::CodeNotFound) => Err(GeoDataError::CountryCodeNotFound(code.to_owned())),
        Err(err) => Err(err),
    }
}

pub fn load_geoip_entry_bytes(entry: &[u8]) -> Result<LoadResult<GeoIp>, GeoDataError> {
    Ok(LoadResult {
        decode_ok: true,
        fallback_ok: false,
        decoded_entry_bytes: entry.len(),
        value: parse_geoip_entry(entry)?,
    })
}

pub fn load_geosite_bytes(data: &[u8], code: &str) -> Result<LoadResult<GeoSite>, GeoDataError> {
    match decode_entry_bytes(data, code) {
        Ok(entry) => load_geosite_entry_bytes(&entry),
        Err(err) if err.is_full_read_fallback_candidate() => {
            let (value, decoded_entry_bytes) = find_geosite_from_list(data, code)?;
            Ok(LoadResult {
                decode_ok: false,
                fallback_ok: true,
                decoded_entry_bytes,
                value,
            })
        }
        Err(GeoDataError::CodeNotFound) => Err(GeoDataError::GeoSiteCodeNotFound(code.to_owned())),
        Err(err) => Err(err),
    }
}

pub fn load_geosite_entry_bytes(entry: &[u8]) -> Result<LoadResult<GeoSite>, GeoDataError> {
    Ok(LoadResult {
        decode_ok: true,
        fallback_ok: false,
        decoded_entry_bytes: entry.len(),
        value: parse_geosite_entry(entry)?,
    })
}

fn find_geoip_from_list(data: &[u8], code: &str) -> Result<(GeoIp, usize), GeoDataError> {
    for entry in entries_from_list(data)? {
        let decoded_entry_bytes = entry.len();
        let geoip = parse_geoip_entry(&entry)?;
        if geoip.country_code.eq_ignore_ascii_case(code) {
            return Ok((geoip, decoded_entry_bytes));
        }
    }
    Err(GeoDataError::CountryCodeNotFound(code.to_owned()))
}

fn find_geosite_from_list(data: &[u8], code: &str) -> Result<(GeoSite, usize), GeoDataError> {
    for entry in entries_from_list(data)? {
        let decoded_entry_bytes = entry.len();
        let geosite = parse_geosite_entry(&entry)?;
        if geosite.country_code.eq_ignore_ascii_case(code) {
            return Ok((geosite, decoded_entry_bytes));
        }
    }
    Err(GeoDataError::GeoSiteCodeNotFound(code.to_owned()))
}

fn parse_geoip_entry(entry: &[u8]) -> Result<GeoIp, GeoDataError> {
    let mut input = entry;
    let mut country_code = String::new();
    let mut cidrs = Vec::new();
    let mut inverse_match = false;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        match (tag >> 3, tag & 0x07) {
            (1, 2) => country_code = string(read_length_delimited(&mut input))?,
            (2, 2) => cidrs.push(parse_cidr(read_length_delimited(&mut input)?)?),
            (3, 0) => inverse_match = read_varint(&mut input)? != 0,
            (_, wire_type) => skip_field(wire_type, &mut input)?,
        }
    }
    Ok(GeoIp {
        country_code,
        cidrs,
        inverse_match,
    })
}

fn parse_geosite_entry(entry: &[u8]) -> Result<GeoSite, GeoDataError> {
    let mut input = entry;
    let mut country_code = String::new();
    let mut domains = Vec::new();
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        match (tag >> 3, tag & 0x07) {
            (1, 2) => country_code = string(read_length_delimited(&mut input))?,
            (2, 2) => domains.push(parse_domain(read_length_delimited(&mut input)?)?),
            (_, wire_type) => skip_field(wire_type, &mut input)?,
        }
    }
    Ok(GeoSite {
        country_code,
        domains,
    })
}

fn parse_cidr(data: &[u8]) -> Result<String, GeoDataError> {
    let mut input = data;
    let mut ip = Vec::new();
    let mut prefix = 0_u32;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        match (tag >> 3, tag & 0x07) {
            (1, 2) => ip = read_length_delimited(&mut input)?.to_vec(),
            (2, 0) => prefix = read_varint(&mut input)? as u32,
            (_, wire_type) => skip_field(wire_type, &mut input)?,
        }
    }

    let addr = match ip.len() {
        4 => Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&ip);
            Ipv6Addr::from(octets).to_string()
        }
        length => return Err(GeoDataError::InvalidIpLength(length)),
    };
    Ok(format!("{addr}/{prefix}"))
}

fn parse_domain(data: &[u8]) -> Result<Domain, GeoDataError> {
    let mut input = data;
    let mut domain_type = DomainType::Plain;
    let mut value = String::new();
    let mut attributes = Vec::new();
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        match (tag >> 3, tag & 0x07) {
            (1, 0) => domain_type = domain_type_from_u64(read_varint(&mut input)?),
            (2, 2) => value = string(read_length_delimited(&mut input))?,
            (3, 2) => attributes.push(parse_attribute_key(read_length_delimited(&mut input)?)?),
            (_, wire_type) => skip_field(wire_type, &mut input)?,
        }
    }
    Ok(Domain {
        domain_type,
        value,
        attributes,
    })
}

fn parse_attribute_key(data: &[u8]) -> Result<String, GeoDataError> {
    let mut input = data;
    let mut key = String::new();
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        match (tag >> 3, tag & 0x07) {
            (1, 2) => key = string(read_length_delimited(&mut input))?,
            (_, wire_type) => skip_field(wire_type, &mut input)?,
        }
    }
    Ok(key)
}

fn domain_type_from_u64(value: u64) -> DomainType {
    match value {
        1 => DomainType::Regex,
        2 => DomainType::RootDomain,
        3 => DomainType::Full,
        _ => DomainType::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::{
        country_code_view, decode_entry_range, decode_entry_reader, decode_entry_view_bytes,
        decode_hex,
    };

    #[test]
    fn streaming_geodata_matches_golden_fixture() {
        let fixture = dae_golden::load_json("geodata/streaming/basic.json").unwrap();
        let geoip = decode_hex(fixture["geoip_hex"].as_str().unwrap()).unwrap();
        let geosite = decode_hex(fixture["geosite_hex"].as_str().unwrap()).unwrap();
        let corrupt_geoip =
            decode_hex(fixture["corrupt_geoip_prefix_hex"].as_str().unwrap()).unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            let kind = case["kind"].as_str().unwrap();
            let code = case["code"].as_str().unwrap();
            let name = case["name"].as_str().unwrap();
            let data = match (kind, name.contains("corrupt")) {
                ("geoip", true) => corrupt_geoip.as_slice(),
                ("geoip", false) => geoip.as_slice(),
                ("geosite", _) => geosite.as_slice(),
                _ => panic!("unexpected geodata fixture kind: {kind}"),
            };

            let decode = decode_entry_bytes(data, code);
            let decode_view = decode_entry_view_bytes(data, code);
            let decode_range = decode_entry_range(data, code);
            assert_eq!(
                decode.is_ok(),
                case["decode_ok"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(decode_view.is_ok(), decode.is_ok(), "{name}");
            assert_eq!(decode_range.is_ok(), decode.is_ok(), "{name}");
            if let (Ok(owned), Ok(view), Ok(range)) = (&decode, decode_view, decode_range) {
                assert_eq!(view, owned.as_slice(), "{name}");
                assert_eq!(&data[range], view, "{name}");
                assert_eq!(
                    country_code_view(view).unwrap(),
                    case["country_code"].as_str().unwrap_or(""),
                    "{name}"
                );
            }
            if let Err(err) = decode {
                assert_eq!(
                    err.to_string(),
                    case["decode_error"].as_str().unwrap(),
                    "{name}"
                );
            }

            assert_eq!(
                decode_entry_reader(Cursor::new(data), code)
                    .as_ref()
                    .map(Vec::len),
                decode_entry_bytes(data, code).as_ref().map(Vec::len),
                "{name}"
            );

            match kind {
                "geoip" => assert_geoip_case(case, data, code, name),
                "geosite" => assert_geosite_case(case, data, code, name),
                _ => unreachable!(),
            }
        }
    }

    fn assert_geoip_case(case: &serde_json::Value, data: &[u8], code: &str, name: &str) {
        let loaded = load_geoip_bytes(data, code);
        assert_eq!(loaded.is_ok(), case["ok"].as_bool().unwrap(), "{name}");
        let Ok(loaded) = loaded else {
            return;
        };

        assert_eq!(
            loaded.decode_ok,
            case["decode_ok"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            loaded.fallback_ok,
            case["fallback_ok"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            loaded.value.country_code,
            case["country_code"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(loaded.value.cidrs, string_array(&case["cidrs"]), "{name}");
    }

    fn assert_geosite_case(case: &serde_json::Value, data: &[u8], code: &str, name: &str) {
        let loaded = load_geosite_bytes(data, code);
        assert_eq!(loaded.is_ok(), case["ok"].as_bool().unwrap(), "{name}");
        let Ok(loaded) = loaded else {
            return;
        };

        assert_eq!(
            loaded.decode_ok,
            case["decode_ok"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            loaded.fallback_ok,
            case["fallback_ok"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            loaded.value.country_code,
            case["country_code"].as_str().unwrap(),
            "{name}"
        );

        let got: Vec<_> = loaded
            .value
            .domains
            .iter()
            .map(|domain| {
                (
                    domain.domain_type.wire_name().to_owned(),
                    domain.value.clone(),
                )
            })
            .collect();
        let want: Vec<_> = case["domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|domain| {
                (
                    domain["type"].as_str().unwrap().to_owned(),
                    domain["value"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
    }

    fn string_array(value: &serde_json::Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }
}
