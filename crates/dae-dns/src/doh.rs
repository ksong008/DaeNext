use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use url::Url;

use crate::error::DnsError;
use crate::message::dns_data_with_zero_id;

pub const DOH_MEDIA_TYPE: &str = "application/dns-message";
pub const DOH_GET_MAX_ENCODED_QUERY_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DohRequest {
    pub method: String,
    pub url: String,
    pub host: String,
    pub accept: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub dns_query: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DohValidationCounters {
    pub status_failure_delta: u64,
    pub content_type_failure_delta: u64,
}

pub fn build_doh_request(
    target: &str,
    hostname: &str,
    path: &str,
    data: &[u8],
) -> Result<DohRequest, DnsError> {
    let request_body = dns_data_with_zero_id(data);
    let encoded = URL_SAFE_NO_PAD.encode(&request_body);
    let base = format!("https://{target}{path}");
    Url::parse(&base).map_err(|err| DnsError::Resolve(err.to_string()))?;

    if encoded.len() <= DOH_GET_MAX_ENCODED_QUERY_BYTES {
        let url = format!("{base}?dns={encoded}");
        Ok(DohRequest {
            method: "GET".to_owned(),
            url,
            host: hostname.to_owned(),
            accept: DOH_MEDIA_TYPE.to_owned(),
            content_type: String::new(),
            body: Vec::new(),
            dns_query: Some(encoded),
        })
    } else {
        Ok(DohRequest {
            method: "POST".to_owned(),
            url: base,
            host: hostname.to_owned(),
            accept: DOH_MEDIA_TYPE.to_owned(),
            content_type: DOH_MEDIA_TYPE.to_owned(),
            body: request_body,
            dns_query: None,
        })
    }
}

pub fn validate_doh_response(
    status_code: u16,
    status: &str,
    content_type: &[u8],
) -> Result<DohValidationCounters, DnsError> {
    if status_code != 200 {
        return Err(DnsError::DohStatus(status.to_owned()));
    }
    if content_type.is_empty() {
        return Ok(DohValidationCounters::default());
    }
    if content_type
        .iter()
        .any(|byte| !byte.is_ascii() || *byte < 0x20 || *byte == 0x7f)
    {
        return Err(DnsError::InvalidDohContentType(
            String::from_utf8_lossy(content_type).into_owned(),
        ));
    }
    let raw = std::str::from_utf8(content_type).map_err(|_| {
        DnsError::InvalidDohContentType(String::from_utf8_lossy(content_type).into_owned())
    })?;
    let media_type = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type != DOH_MEDIA_TYPE {
        return Err(DnsError::UnexpectedDohContentType(raw.to_owned()));
    }
    Ok(DohValidationCounters::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{decode_hex, encode_hex};

    #[test]
    fn doh_get_post_and_validation_match_golden_fixture() {
        let fixture = dae_golden::load_json("dns/doh/get_post_validation.json").unwrap();
        assert_eq!(
            DOH_GET_MAX_ENCODED_QUERY_BYTES as u64,
            fixture["get_max_encoded_query_bytes"].as_u64().unwrap()
        );

        let get = &fixture["get_small_payload"];
        let req = build_doh_request(
            get["target"].as_str().unwrap(),
            get["hostname"].as_str().unwrap(),
            get["path"].as_str().unwrap(),
            &decode_hex(get["input_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(req.method, get["method"].as_str().unwrap());
        assert_eq!(req.accept, get["accept"].as_str().unwrap());
        assert_eq!(req.content_type, get["content_type"].as_str().unwrap());
        assert_eq!(req.host, get["host"].as_str().unwrap());
        assert_eq!(req.dns_query.as_deref(), get["dns_query"].as_str());
        assert_eq!(req.url, get["url"].as_str().unwrap());
        assert_eq!(
            encode_hex(&crate::message::dns_data_with_zero_id(
                &decode_hex(get["input_hex"].as_str().unwrap()).unwrap()
            )),
            get["zero_id_hex"].as_str().unwrap()
        );

        let post = &fixture["post_large_payload"];
        let input = {
            let mut bytes = vec![0x12, 0x34];
            bytes.extend(std::iter::repeat_n(0xab, 1024));
            bytes
        };
        let req =
            build_doh_request("1.1.1.1:443", "dns.example.com", "/dns-query", &input).unwrap();
        assert_eq!(req.method, post["method"].as_str().unwrap());
        assert_eq!(req.accept, post["accept"].as_str().unwrap());
        assert_eq!(req.content_type, post["content_type"].as_str().unwrap());
        assert_eq!(
            req.dns_query.is_some(),
            post["query_has_dns"].as_bool().unwrap()
        );
        assert_eq!(req.body.len(), post["body_len"].as_u64().unwrap() as usize);
        assert_eq!(
            &encode_hex(&req.body[..4]),
            post["zero_id_prefix"].as_str().unwrap()
        );

        for case in fixture["validation"].as_array().unwrap() {
            let status = case["status"].as_str().unwrap();
            let status_code = status.split_once(' ').unwrap().0.parse::<u16>().unwrap();
            let content_type = if let Some(hex) = case["content_type_hex"].as_str() {
                decode_hex(hex).unwrap()
            } else {
                case["content_type"].as_str().unwrap().as_bytes().to_vec()
            };
            let got = validate_doh_response(status_code, status, &content_type);
            assert_eq!(
                got.is_ok(),
                case["ok"].as_bool().unwrap(),
                "{}",
                case["name"].as_str().unwrap()
            );
            if let Err(err) = got {
                if let Some(want) = case["error"].as_str() {
                    assert_eq!(err.to_string(), want);
                }
                if let Some(want) = case["error_contains"].as_str() {
                    assert!(err.to_string().contains(want), "{err}");
                }
            }
        }
    }
}
