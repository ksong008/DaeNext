use std::fmt;
use std::str;

pub const MAGIC_NETWORK_TYPE: u8 = 0;
const MAGIC_NETWORK_FRAME_OVERHEAD: usize = 2 + 4 + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MagicNetworkEncoding {
    PlainWhenEligible,
    Framed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MagicNetwork {
    pub network: Vec<u8>,
    pub mark: u32,
    pub mptcp: bool,
}

impl MagicNetwork {
    pub fn network_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.network)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MagicNetworkError {
    UnknownEncoding,
    NetworkTooLong { len: usize },
    MarkTooBig,
    OutputTooSmall { needed: usize, available: usize },
}

impl fmt::Display for MagicNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEncoding => f.write_str("unknown magic network encoding"),
            Self::NetworkTooLong { len } => write!(f, "network too long: {len}"),
            Self::MarkTooBig => f.write_str("mark is too big"),
            Self::OutputTooSmall { needed, available } => {
                write!(f, "output too small: need {needed} bytes, have {available}")
            }
        }
    }
}

impl std::error::Error for MagicNetworkError {}

pub fn encode_magic_network(
    network: impl AsRef<[u8]>,
    mark: u32,
    mptcp: bool,
) -> Result<Vec<u8>, MagicNetworkError> {
    encode_magic_network_with_encoding(
        network,
        mark,
        mptcp,
        MagicNetworkEncoding::PlainWhenEligible,
    )
}

pub fn encode_magic_network_with_encoding(
    network: impl AsRef<[u8]>,
    mark: u32,
    mptcp: bool,
    encoding: MagicNetworkEncoding,
) -> Result<Vec<u8>, MagicNetworkError> {
    let network_bytes = network.as_ref();
    let encoded_len = magic_network_encoded_len(network_bytes, mark, mptcp, encoding)?;
    let mut encoded = Vec::with_capacity(encoded_len);
    write_magic_network_to_vec(network_bytes, mark, mptcp, encoding, &mut encoded)?;
    Ok(encoded)
}

pub fn magic_network_encoded_len(
    network: impl AsRef<[u8]>,
    mark: u32,
    mptcp: bool,
    encoding: MagicNetworkEncoding,
) -> Result<usize, MagicNetworkError> {
    let network_bytes = network.as_ref();
    if uses_plaintext_encoding(network_bytes, mark, mptcp, encoding) {
        return Ok(network_bytes.len());
    }

    if network_bytes.len() > u8::MAX as usize {
        return Err(MagicNetworkError::NetworkTooLong {
            len: network_bytes.len(),
        });
    }
    Ok(MAGIC_NETWORK_FRAME_OVERHEAD + network_bytes.len())
}

pub fn write_magic_network_to_vec(
    network: impl AsRef<[u8]>,
    mark: u32,
    mptcp: bool,
    encoding: MagicNetworkEncoding,
    output: &mut Vec<u8>,
) -> Result<usize, MagicNetworkError> {
    let network_bytes = network.as_ref();
    let encoded_len = magic_network_encoded_len(network_bytes, mark, mptcp, encoding)?;
    output.reserve(encoded_len);
    if uses_plaintext_encoding(network_bytes, mark, mptcp, encoding) {
        output.extend_from_slice(network_bytes);
    } else {
        output.push(MAGIC_NETWORK_TYPE);
        output.push(network_bytes.len() as u8);
        output.extend_from_slice(network_bytes);
        output.extend_from_slice(&mark.to_be_bytes());
        output.push(u8::from(mptcp));
    }
    Ok(encoded_len)
}

pub fn write_magic_network_to_slice(
    network: impl AsRef<[u8]>,
    mark: u32,
    mptcp: bool,
    encoding: MagicNetworkEncoding,
    output: &mut [u8],
) -> Result<usize, MagicNetworkError> {
    let network_bytes = network.as_ref();
    let encoded_len = magic_network_encoded_len(network_bytes, mark, mptcp, encoding)?;
    if output.len() < encoded_len {
        return Err(MagicNetworkError::OutputTooSmall {
            needed: encoded_len,
            available: output.len(),
        });
    }
    if uses_plaintext_encoding(network_bytes, mark, mptcp, encoding) {
        output[..encoded_len].copy_from_slice(network_bytes);
    } else {
        output[0] = MAGIC_NETWORK_TYPE;
        output[1] = network_bytes.len() as u8;
        output[2..2 + network_bytes.len()].copy_from_slice(network_bytes);
        let mark_offset = 2 + network_bytes.len();
        output[mark_offset..mark_offset + 4].copy_from_slice(&mark.to_be_bytes());
        output[mark_offset + 4] = u8::from(mptcp);
    }
    Ok(encoded_len)
}

pub fn parse_magic_network(input: &[u8]) -> Result<MagicNetwork, MagicNetworkError> {
    if input.is_empty() {
        return Ok(MagicNetwork {
            network: Vec::new(),
            mark: 0,
            mptcp: false,
        });
    }

    if is_plaintext_eligible(input) {
        return Ok(MagicNetwork {
            network: input.to_vec(),
            mark: 0,
            mptcp: false,
        });
    }

    if input.len() < 2 || input[0] != MAGIC_NETWORK_TYPE {
        return Err(MagicNetworkError::UnknownEncoding);
    }

    let network_len = input[1] as usize;
    let min_len = 2 + network_len + 4 + 1;
    if input.len() < min_len {
        return Err(MagicNetworkError::UnknownEncoding);
    }

    let network_start = 2;
    let network_end = network_start + network_len;
    let mark_start = network_end;
    let mark_end = mark_start + 4;
    let network = input[network_start..network_end].to_vec();
    let mark = u32::from_be_bytes([
        input[mark_start],
        input[mark_start + 1],
        input[mark_start + 2],
        input[mark_start + 3],
    ]);

    if mark_exceeds_i32_compat(mark) {
        return Err(MagicNetworkError::MarkTooBig);
    }

    Ok(MagicNetwork {
        network,
        mark,
        mptcp: input[mark_end] == 1,
    })
}

/// Decide whether a network is carried in the plaintext (unencoded) form.
///
/// Both `encode_magic_network` and `parse_magic_network` use this same
/// predicate so the plaintext/encoded decision is symmetric and round-trips
/// are exact: a network is plaintext only when its first UTF-8 char is
/// printable AND it contains no control byte anywhere. A network whose first
/// char is not printable (e.g. `b"\x01tcp"`) must not be emitted as plaintext
/// because the parser would not classify it as plaintext either and would fail
/// to decode it; it always takes the encoded form (which starts with the
/// control byte MAGIC_NETWORK_TYPE, forcing the parser into the encoded path).
/// Requiring "no control bytes anywhere" additionally guarantees the plaintext
/// form can never be confused with the encoded layout. Control bytes are
/// ASCII controls (0x00-0x1F), DEL (0x7F) and C1 controls (0x80-0x9F);
/// printable multi-byte UTF-8 and non-UTF-8 payloads without control bytes
/// (e.g. `b"tcp\xff"`) keep the historical plaintext behavior.
fn is_plaintext_eligible(network: &[u8]) -> bool {
    if !starts_with_printable_rune(network) {
        return false;
    }
    !network
        .iter()
        .any(|byte| *byte < 0x20 || (0x7F..=0x9F).contains(byte))
}

fn uses_plaintext_encoding(
    network: &[u8],
    mark: u32,
    mptcp: bool,
    encoding: MagicNetworkEncoding,
) -> bool {
    encoding == MagicNetworkEncoding::PlainWhenEligible
        && mark == 0
        && !mptcp
        && is_plaintext_eligible(network)
}

fn starts_with_printable_rune(input: &[u8]) -> bool {
    let Some(ch) = first_utf8_char(input) else {
        return false;
    };

    !ch.is_control()
}

fn first_utf8_char(input: &[u8]) -> Option<char> {
    for len in 1..=4 {
        if input.len() < len {
            return None;
        }
        let Ok(text) = str::from_utf8(&input[..len]) else {
            continue;
        };
        let mut chars = text.chars();
        let ch = chars.next()?;
        if ch.len_utf8() == len {
            return Some(ch);
        }
    }
    None
}

#[cfg(target_pointer_width = "32")]
fn mark_exceeds_i32_compat(mark: u32) -> bool {
    u32::BITS - mark.leading_zeros() >= usize::BITS
}

#[cfg(not(target_pointer_width = "32"))]
fn mark_exceeds_i32_compat(_mark: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_network_roundtrip_matches_golden_fixture() {
        let fixture = dae_golden::load_json("abi/magic_network/mark_mptcp.json").unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            let input = &case["input"];
            let want = &case["want"];
            let network = input["network"].as_str().unwrap();
            let mark = input["mark"].as_u64().unwrap() as u32;
            let mptcp = input["mptcp"].as_bool().unwrap();

            let encoded = encode_magic_network(network, mark, mptcp).unwrap();
            assert_eq!(hex_encode(&encoded), want["encoded_hex"].as_str().unwrap());

            let parsed = parse_magic_network(&encoded).unwrap();
            assert_eq!(
                parsed.network_str().unwrap(),
                want["parsed"]["network"].as_str().unwrap()
            );
            assert_eq!(parsed.mark, want["parsed"]["mark"].as_u64().unwrap() as u32);
            assert_eq!(parsed.mptcp, want["parsed"]["mptcp"].as_bool().unwrap());
        }
    }

    #[test]
    fn explicit_encoding_modes_keep_plain_and_framed_golden_vectors() {
        let plain = encode_magic_network_with_encoding(
            "tcp",
            0,
            false,
            MagicNetworkEncoding::PlainWhenEligible,
        )
        .unwrap();
        assert_eq!(plain, b"tcp");

        let framed =
            encode_magic_network_with_encoding("tcp", 0, false, MagicNetworkEncoding::Framed)
                .unwrap();
        assert_eq!(hex_encode(&framed), "00037463700000000000");
        assert_eq!(
            parse_magic_network(&framed).unwrap(),
            MagicNetwork {
                network: b"tcp".to_vec(),
                mark: 0,
                mptcp: false,
            }
        );
    }

    #[test]
    fn length_vec_and_slice_apis_emit_identical_framed_bytes() {
        let expected = encode_magic_network_with_encoding(
            b"udp\xff".as_slice(),
            u32::MAX,
            true,
            MagicNetworkEncoding::Framed,
        )
        .unwrap();
        let len = magic_network_encoded_len(
            b"udp\xff".as_slice(),
            u32::MAX,
            true,
            MagicNetworkEncoding::Framed,
        )
        .unwrap();
        assert_eq!(len, expected.len());

        let mut appended = b"prefix".to_vec();
        let written = write_magic_network_to_vec(
            b"udp\xff".as_slice(),
            u32::MAX,
            true,
            MagicNetworkEncoding::Framed,
            &mut appended,
        )
        .unwrap();
        assert_eq!(written, len);
        assert_eq!(&appended[b"prefix".len()..], expected);

        let mut slice = vec![0xa5; len + 1];
        let written = write_magic_network_to_slice(
            b"udp\xff".as_slice(),
            u32::MAX,
            true,
            MagicNetworkEncoding::Framed,
            &mut slice,
        )
        .unwrap();
        assert_eq!(written, len);
        assert_eq!(&slice[..len], expected);
        assert_eq!(slice[len], 0xa5);
    }

    #[test]
    fn framed_length_and_output_capacity_are_bounded_explicitly() {
        let max_network = vec![b'x'; u8::MAX as usize];
        assert_eq!(
            magic_network_encoded_len(&max_network, 0, false, MagicNetworkEncoding::Framed,)
                .unwrap(),
            max_network.len() + MAGIC_NETWORK_FRAME_OVERHEAD
        );

        let oversized = vec![b'x'; u8::MAX as usize + 1];
        assert_eq!(
            magic_network_encoded_len(&oversized, 0, false, MagicNetworkEncoding::Framed,),
            Err(MagicNetworkError::NetworkTooLong {
                len: oversized.len()
            })
        );
        assert_eq!(
            magic_network_encoded_len(
                &oversized,
                0,
                false,
                MagicNetworkEncoding::PlainWhenEligible,
            )
            .unwrap(),
            oversized.len()
        );

        let mut short = [0_u8; 9];
        assert_eq!(
            write_magic_network_to_slice("tcp", 0, false, MagicNetworkEncoding::Framed, &mut short,),
            Err(MagicNetworkError::OutputTooSmall {
                needed: 10,
                available: 9,
            })
        );
    }

    #[test]
    fn parser_keeps_netproxy_edge_cases() {
        assert_eq!(
            parse_magic_network(b"").unwrap(),
            MagicNetwork {
                network: Vec::new(),
                mark: 0,
                mptcp: false
            }
        );
        assert_eq!(
            parse_magic_network(&[1, 0]),
            Err(MagicNetworkError::UnknownEncoding)
        );

        let mut encoded = encode_magic_network("tcp", 1, false).unwrap();
        encoded.extend_from_slice(b"trailing");
        assert_eq!(parse_magic_network(&encoded).unwrap().mark, 1);

        let plain = parse_magic_network(b"tcp\xff").unwrap();
        assert_eq!(plain.network, b"tcp\xff");
    }

    #[test]
    fn control_char_networks_roundtrip_through_the_encoded_form() {
        // Networks that are not plaintext-eligible (leading control char,
        // embedded control byte) must be encoded and must decode back to the
        // exact original bytes. Before the fix, a leading control char was
        // emitted as plaintext but the parser refused to treat it as
        // plaintext, breaking the round-trip.
        let cases: &[&[u8]] = &[
            b"\x01tcp",
            b"\x00udp",
            b"\x1b",
            b"tcp\x00",
            b"a\x01b",
            b"\xc2\x80tcp", // U+0080 (C1 control) as first char
        ];
        for network in cases {
            let encoded = encode_magic_network(*network, 0, false).unwrap();
            assert_ne!(&encoded, network, "non-plaintext network must be encoded");
            let parsed = parse_magic_network(&encoded).unwrap();
            assert_eq!(parsed.network, *network, "round-trip for {network:?}");
            assert_eq!(parsed.mark, 0);
            assert!(!parsed.mptcp);
        }

        // mark/mptcp ride along the encoded form for these networks too.
        let encoded = encode_magic_network(b"\x01tcp", 7, true).unwrap();
        let parsed = parse_magic_network(&encoded).unwrap();
        assert_eq!(parsed.network, b"\x01tcp");
        assert_eq!(parsed.mark, 7);
        assert!(parsed.mptcp);
    }

    #[test]
    fn plaintext_with_control_chars_is_no_longer_parsed_as_plaintext() {
        // The plaintext form is only produced for control-free networks, so a
        // plaintext-looking input that contains a control byte must not be
        // accepted as plaintext (it would otherwise be ambiguous); it must be
        // decoded from the encoded layout instead.
        assert_eq!(
            parse_magic_network(b"tcp\x00"),
            Err(MagicNetworkError::UnknownEncoding)
        );
        assert_eq!(
            parse_magic_network(b"\xff\xfe"),
            Err(MagicNetworkError::UnknownEncoding)
        );

        // Printable, control-free plaintext still round-trips as before,
        // including non-UTF-8 payloads without control bytes.
        let plain = parse_magic_network(b"tcp").unwrap();
        assert_eq!(plain.network, b"tcp");
        assert_eq!(encode_magic_network("tcp", 0, false).unwrap(), b"tcp");
        let raw = parse_magic_network(b"tcp\xff").unwrap();
        assert_eq!(raw.network, b"tcp\xff");
        let raw = parse_magic_network(b"tcp\xff\xfe").unwrap();
        assert_eq!(raw.network, b"tcp\xff\xfe");
        assert_eq!(
            encode_magic_network(b"tcp\xff\xfe", 0, false).unwrap(),
            b"tcp\xff\xfe"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
