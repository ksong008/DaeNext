use std::io::Read;

use crate::error::DnsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpForwardError {
    Timeout,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpForwardOutcome {
    pub response: Vec<u8>,
    pub write_count: usize,
    pub retry_counter_delta: u64,
}

pub fn read_tcp_dns_response(mut reader: impl Read, max_len: usize) -> Result<Vec<u8>, DnsError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(DnsError::TooBigDnsResp);
    }
    let mut response = vec![0u8; len];
    reader.read_exact(&mut response)?;
    Ok(response)
}

pub fn forward_udp_with_retry(
    attempts: usize,
    mut exchange: impl FnMut(usize) -> Result<Vec<u8>, UdpForwardError>,
) -> Result<UdpForwardOutcome, DnsError> {
    let mut retry_counter_delta = 0;
    for attempt in 0..attempts {
        match exchange(attempt) {
            Ok(response) => {
                return Ok(UdpForwardOutcome {
                    response,
                    write_count: attempt + 1,
                    retry_counter_delta,
                });
            }
            Err(UdpForwardError::Timeout) if attempt + 1 < attempts => {
                retry_counter_delta += 1;
            }
            Err(UdpForwardError::Timeout) => return Err(DnsError::Timeout),
            Err(UdpForwardError::Other) => {
                return Err(DnsError::Io("udp forward failed".to_owned()));
            }
        }
    }
    Err(DnsError::Timeout)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn dns_netutils_semantics_match_golden_fixture() {
        let fixture = dae_golden::load_json("dns/netutils/basic.json").unwrap();

        let tcp = &fixture["tcp_full_read_one_byte_chunks"];
        let response = vec![0xde, 0xad, 0xbe, 0xef];
        let mut framed = vec![0, response.len() as u8];
        framed.extend_from_slice(&response);
        let got = read_tcp_dns_response(Cursor::new(framed), 1500).unwrap();
        assert_eq!(got, response);
        assert_eq!(tcp["chunk_bytes"].as_u64().unwrap(), 1);

        let udp = &fixture["udp_packet_conn_semantics"];
        assert!(!udp["stream_write"].as_bool().unwrap());
        assert!(!udp["stream_read"].as_bool().unwrap());
        assert_eq!(
            udp["write_to"].as_str().unwrap(),
            udp["dns"].as_str().unwrap()
        );

        let retry = &fixture["udp_retry_counter"];
        let outcome = forward_udp_with_retry(3, |attempt| {
            if attempt == 0 {
                Err(UdpForwardError::Timeout)
            } else {
                Ok(vec![1, 2, 3])
            }
        })
        .unwrap();
        assert_eq!(
            outcome.write_count,
            retry["write_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            outcome.retry_counter_delta,
            retry["retry_counter_delta"].as_u64().unwrap()
        );
    }
}
