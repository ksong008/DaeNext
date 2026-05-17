pub mod error;
pub mod http;
pub mod normalize;
pub mod packet;
pub mod tls;

pub use error::{SniffingError, is_sniffing_error};
pub use http::sniff_http;
pub use normalize::normalize_domain;
pub use packet::{PACKET_SNIFFER_MAX_BUFFERED_BYTES, PACKET_SNIFFER_MAX_CHUNKS, PacketSniffer};
pub use tls::sniff_tls;

pub fn sniff_tcp(data: &[u8]) -> Result<String, SniffingError> {
    match sniff_tls(data) {
        Ok(domain) => return Ok(normalize_domain(&domain)),
        Err(SniffingError::NotApplicable) => {}
        Err(SniffingError::NeedMore) => {
            return Err(SniffingError::Message(
                "sniffing error: need more: sniffing error: not applicable: context deadline exceeded"
                    .to_owned(),
            ));
        }
        Err(err) => return Err(err),
    }

    sniff_http(data).map(|domain| normalize_domain(&domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing_basic_matches_golden_fixture() {
        let fixture = dae_golden::load_json("sniffing/basic.json").unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            match case["name"].as_str().unwrap() {
                "http-host-normalize-and-retain" | "tls-google-sni" => {
                    let input = decode_hex(case["input_hex"].as_str().unwrap());
                    let got = sniff_tcp(&input);
                    assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap());
                    match got {
                        Ok(domain) => assert_eq!(domain, case["domain"].as_str().unwrap()),
                        Err(err) => assert_eq!(err.to_string(), case["error"].as_str().unwrap()),
                    }
                }
                "packet-data-detached-copy" => {
                    let packet = PacketSniffer::new(case["input"].as_str().unwrap().as_bytes());
                    let mut copied = packet.data();
                    copied[0][0] = b'H';
                    let view = packet.data_view();
                    assert_eq!(
                        std::str::from_utf8(view[0]).unwrap(),
                        case["data_view"].as_str().unwrap()
                    );
                    assert_eq!(
                        std::str::from_utf8(view[0]).unwrap() == "hello",
                        case["copy_detached"].as_bool().unwrap()
                    );
                }
                "packet-quic-buffer-cap" => {
                    let mut packet = PacketSniffer::new(&[]);
                    packet.append_data(&vec![0; case["append_size"].as_u64().unwrap() as usize]);
                    let err = packet.sniff_udp().unwrap_err();
                    assert_eq!(packet.need_more(), case["need_more"].as_bool().unwrap());
                    assert_eq!(err.to_string(), case["error"].as_str().unwrap());
                    assert_eq!(
                        is_sniffing_error(&err),
                        case["is_sniff_err"].as_bool().unwrap()
                    );
                }
                name => panic!("unexpected sniffing fixture case: {name}"),
            }
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                ((hi << 4) | lo) as u8
            })
            .collect()
    }
}
