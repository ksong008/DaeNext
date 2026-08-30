use std::collections::VecDeque;

use dae_outbound_core::error::OutboundError;

include!("huffman_table.rs");

const STATIC_TABLE: [(&str, Option<&str>); 61] = [
    (":authority", None),
    (":method", Some("GET")),
    (":method", Some("POST")),
    (":path", Some("/")),
    (":path", Some("/index.html")),
    (":scheme", Some("http")),
    (":scheme", Some("https")),
    (":status", Some("200")),
    (":status", Some("204")),
    (":status", Some("206")),
    (":status", Some("304")),
    (":status", Some("400")),
    (":status", Some("404")),
    (":status", Some("500")),
    ("accept-charset", None),
    ("accept-encoding", Some("gzip, deflate")),
    ("accept-language", None),
    ("accept-ranges", None),
    ("accept", None),
    ("access-control-allow-origin", None),
    ("age", None),
    ("allow", None),
    ("authorization", None),
    ("cache-control", None),
    ("content-disposition", None),
    ("content-encoding", None),
    ("content-language", None),
    ("content-length", None),
    ("content-location", None),
    ("content-range", None),
    ("content-type", None),
    ("cookie", None),
    ("date", None),
    ("etag", None),
    ("expect", None),
    ("expires", None),
    ("from", None),
    ("host", None),
    ("if-match", None),
    ("if-modified-since", None),
    ("if-none-match", None),
    ("if-range", None),
    ("if-unmodified-since", None),
    ("last-modified", None),
    ("link", None),
    ("location", None),
    ("max-forwards", None),
    ("proxy-authenticate", None),
    ("proxy-authorization", None),
    ("range", None),
    ("referer", None),
    ("refresh", None),
    ("retry-after", None),
    ("server", None),
    ("set-cookie", None),
    ("strict-transport-security", None),
    ("transfer-encoding", None),
    ("user-agent", None),
    ("vary", None),
    ("via", None),
    ("www-authenticate", None),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpackHeader {
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;
const MAX_HEADER_FIELDS: usize = 128;
const MAX_DECODED_HEADER_BYTES: usize = 128 * 1024;
const MAX_DYNAMIC_TABLE_BYTES: usize = 4 * 1024;
const MAX_HPACK_STRING_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct HpackDynamicTable {
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    bytes: usize,
    max_bytes: usize,
}

impl HpackDynamicTable {
    fn new() -> Self {
        Self {
            max_bytes: MAX_DYNAMIC_TABLE_BYTES,
            ..Self::default()
        }
    }

    fn set_max_bytes(&mut self, max_bytes: usize) -> Result<(), OutboundError> {
        if max_bytes > MAX_DYNAMIC_TABLE_BYTES {
            return Err(hpack_error(format!(
                "HPACK dynamic table size {max_bytes} exceeds {MAX_DYNAMIC_TABLE_BYTES}"
            )));
        }
        self.max_bytes = max_bytes;
        self.evict_to_budget();
        Ok(())
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> Result<(), OutboundError> {
        let entry_bytes = name
            .len()
            .checked_add(value.len())
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or_else(|| hpack_error("HPACK dynamic entry size overflow"))?;
        if entry_bytes > self.max_bytes {
            self.entries.clear();
            self.bytes = 0;
            return Ok(());
        }
        self.bytes = self
            .bytes
            .checked_add(entry_bytes)
            .ok_or_else(|| hpack_error("HPACK dynamic table size overflow"))?;
        self.entries.push_front((name, value));
        self.evict_to_budget();
        Ok(())
    }

    fn evict_to_budget(&mut self) {
        while self.bytes > self.max_bytes {
            let Some((name, value)) = self.entries.pop_back() else {
                self.bytes = 0;
                break;
            };
            self.bytes = self
                .bytes
                .saturating_sub(name.len().saturating_add(value.len()).saturating_add(32));
        }
    }

    fn get(&self, index: usize) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.entries.get(index)
    }
}

pub fn decode_header_block(block: &[u8]) -> Result<Vec<HpackHeader>, OutboundError> {
    if block.len() > MAX_HEADER_BLOCK_BYTES {
        return Err(hpack_error(format!(
            "HPACK header block exceeds {MAX_HEADER_BLOCK_BYTES} bytes"
        )));
    }
    let mut headers = Vec::new();
    let mut dynamic = HpackDynamicTable::new();
    let mut decoded_bytes = 0_usize;
    let mut offset = 0_usize;
    let mut saw_header = false;
    while offset < block.len() {
        let first = block[offset];
        let header = if first & 0x80 != 0 {
            let (index, consumed) = decode_integer(block, offset, 7)?;
            offset += consumed;
            Some(indexed_entry(index, &dynamic)?)
        } else if first & 0x40 != 0 {
            let (index, consumed) = decode_integer(block, offset, 6)?;
            offset += consumed;
            let header = literal_header(block, &mut offset, index, &dynamic)?;
            dynamic.insert(header.name.clone(), header.value.clone())?;
            Some(header)
        } else if first & 0x20 != 0 {
            if saw_header {
                return Err(hpack_error(
                    "HPACK dynamic table size update appears after a header field",
                ));
            }
            let (max_bytes, consumed) = decode_integer(block, offset, 5)?;
            offset += consumed;
            dynamic.set_max_bytes(max_bytes)?;
            None
        } else {
            let (index, consumed) = decode_integer(block, offset, 4)?;
            offset += consumed;
            Some(literal_header(block, &mut offset, index, &dynamic)?)
        };

        if let Some(header) = header {
            saw_header = true;
            decoded_bytes = decoded_bytes
                .checked_add(header.name.len())
                .and_then(|bytes| bytes.checked_add(header.value.len()))
                .ok_or_else(|| hpack_error("HPACK decoded header size overflow"))?;
            if decoded_bytes > MAX_DECODED_HEADER_BYTES {
                return Err(hpack_error(format!(
                    "HPACK decoded headers exceed {MAX_DECODED_HEADER_BYTES} bytes"
                )));
            }
            if headers.len() >= MAX_HEADER_FIELDS {
                return Err(hpack_error(format!(
                    "HPACK header count exceeds {MAX_HEADER_FIELDS}"
                )));
            }
            headers.push(header);
        }
    }
    Ok(headers)
}

fn literal_header(
    block: &[u8],
    offset: &mut usize,
    index: usize,
    dynamic: &HpackDynamicTable,
) -> Result<HpackHeader, OutboundError> {
    let name = if index == 0 {
        let (name, consumed) = decode_hpack_string(block, *offset)?;
        *offset = offset
            .checked_add(consumed)
            .ok_or_else(|| hpack_error("HPACK literal name offset overflow"))?;
        name
    } else {
        indexed_name(index, dynamic)?
    };
    let (value, consumed) = decode_hpack_string(block, *offset)?;
    *offset = offset
        .checked_add(consumed)
        .ok_or_else(|| hpack_error("HPACK literal value offset overflow"))?;
    Ok(HpackHeader { name, value })
}

fn indexed_entry(index: usize, dynamic: &HpackDynamicTable) -> Result<HpackHeader, OutboundError> {
    if index == 0 {
        return Err(hpack_error("HPACK index zero is invalid"));
    }
    if index <= STATIC_TABLE.len() {
        let (name, value) = STATIC_TABLE[index - 1];
        return Ok(HpackHeader {
            name: name.as_bytes().to_vec(),
            value: value.unwrap_or_default().as_bytes().to_vec(),
        });
    }
    let dynamic_index = index - STATIC_TABLE.len() - 1;
    let (name, value) = dynamic
        .get(dynamic_index)
        .ok_or_else(|| hpack_error(format!("HPACK dynamic index {index} out of range")))?;
    Ok(HpackHeader {
        name: name.clone(),
        value: value.clone(),
    })
}

fn indexed_name(index: usize, dynamic: &HpackDynamicTable) -> Result<Vec<u8>, OutboundError> {
    if index == 0 {
        return Err(hpack_error("HPACK name index zero requires a literal name"));
    }
    if index <= STATIC_TABLE.len() {
        return Ok(STATIC_TABLE[index - 1].0.as_bytes().to_vec());
    }
    let dynamic_index = index - STATIC_TABLE.len() - 1;
    dynamic
        .get(dynamic_index)
        .map(|(name, _)| name.clone())
        .ok_or_else(|| hpack_error(format!("HPACK dynamic name index {index} out of range")))
}

fn decode_integer(
    block: &[u8],
    start: usize,
    prefix_bits: u8,
) -> Result<(usize, usize), OutboundError> {
    if start >= block.len() {
        return Err(hpack_error("HPACK integer truncated"));
    }
    if !(1..=8).contains(&prefix_bits) {
        return Err(hpack_error("HPACK integer prefix is invalid"));
    }
    let prefix_max = if prefix_bits == 8 {
        u8::MAX
    } else {
        ((1_u16 << prefix_bits) - 1) as u8
    };
    let first = block[start];
    let mut value = usize::from(first & prefix_max);
    if value < usize::from(prefix_max) {
        return Ok((value, 1));
    }
    let mut shift = 0_usize;
    let mut offset = start + 1;
    loop {
        if offset >= block.len() {
            return Err(hpack_error("HPACK integer continuation truncated"));
        }
        let byte = block[offset];
        offset += 1;
        value = value
            .checked_add(
                usize::from(byte & 0x7f)
                    .checked_shl(shift as u32)
                    .ok_or_else(|| hpack_error("HPACK integer overflow"))?,
            )
            .ok_or_else(|| hpack_error("HPACK integer overflow"))?;
        if byte & 0x80 == 0 {
            return Ok((value, offset - start));
        }
        shift += 7;
        if shift > 63 {
            return Err(hpack_error("HPACK integer too long"));
        }
    }
}

fn decode_hpack_string(block: &[u8], start: usize) -> Result<(Vec<u8>, usize), OutboundError> {
    if start >= block.len() {
        return Err(hpack_error("HPACK string truncated"));
    }
    let huffman = block[start] & 0x80 != 0;
    let (len, consumed) = decode_integer(block, start, 7)?;
    if len > MAX_HPACK_STRING_BYTES {
        return Err(hpack_error(format!(
            "HPACK string exceeds {MAX_HPACK_STRING_BYTES} bytes"
        )));
    }
    let data_start = start
        .checked_add(consumed)
        .ok_or_else(|| hpack_error("HPACK string offset overflow"))?;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| hpack_error("HPACK string length overflow"))?;
    if data_end > block.len() {
        return Err(hpack_error("HPACK string length exceeds block"));
    }
    let raw = &block[data_start..data_end];
    let out = if huffman {
        decode_huffman(raw)?
    } else {
        raw.to_vec()
    };
    Ok((out, consumed + len))
}

fn decode_huffman(input: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::new();
    let mut code = 0_u32;
    let mut code_len = 0_u8;
    for &byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            code_len = code_len
                .checked_add(1)
                .ok_or_else(|| hpack_error("HPACK Huffman code length overflow"))?;
            if let Some((symbol, _)) = HUFFMAN_TABLE
                .iter()
                .enumerate()
                .find(|(_, (candidate, len))| *len == code_len && *candidate == code)
            {
                out.push(symbol as u8);
                if out.len() > MAX_HPACK_STRING_BYTES {
                    return Err(hpack_error(format!(
                        "HPACK Huffman output exceeds {MAX_HPACK_STRING_BYTES} bytes"
                    )));
                }
                code = 0;
                code_len = 0;
                continue;
            }
            let has_prefix = HUFFMAN_TABLE.iter().any(|(candidate, len)| {
                *len > code_len && (*candidate >> (*len - code_len)) == code
            });
            if !has_prefix {
                return Err(hpack_error("invalid HPACK Huffman code"));
            }
        }
    }
    if code_len > 7 || (code_len != 0 && code != (1_u32 << code_len) - 1) {
        return Err(hpack_error("invalid HPACK Huffman padding"));
    }
    Ok(out)
}

fn hpack_error(message: impl Into<String>) -> OutboundError {
    OutboundError::BadSharedTransport(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_literal_new_name() {
        // 0x00 + len(4) "test" + len(12) "hello world"
        let block = [
            0x00, 0x04, b't', b'e', b's', b't', 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w',
            b'o', b'r', b'l', b'd',
        ];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, b"test");
        assert_eq!(headers[0].value, b"hello world");
    }

    #[test]
    fn decodes_indexed_name_with_value() {
        // 0x01 + 0x02 "ok" :method=GET? no——index 1 = :authority
        // literal with indexed name: 0100_0001 (index 1) + len(2) "ok"
        let block = [0x41, 0x02, b'o', b'k'];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers[0].name, b":authority");
        assert_eq!(headers[0].value, b"ok");
    }

    #[test]
    fn decodes_indexed_entry() {
        // 0x82 = index 2 = :method GET
        let block = [0x82];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers[0].name, b":method");
        assert_eq!(headers[0].value, b"GET");
    }

    #[test]
    fn rejects_truncated_block() {
        assert!(decode_header_block(&[0x00, 0x05, b'a']).is_err());
    }

    #[test]
    fn decodes_dynamic_entry_inserted_in_same_block() {
        let block = [0x40, 0x01, b'x', 0x01, b'y', 0xbe];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].name, b"x");
        assert_eq!(headers[0].value, b"y");
        assert_eq!(headers[1], headers[0]);
    }

    #[test]
    fn decodes_never_indexed_literal() {
        let block = [0x10, 0x01, b'x', 0x01, b'y'];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, b"x");
        assert_eq!(headers[0].value, b"y");
    }

    #[test]
    fn rejects_dynamic_size_update_after_header() {
        assert!(decode_header_block(&[0x82, 0x20]).is_err());
    }
}

#[cfg(test)]
mod huffman_tests {
    use super::HUFFMAN_TABLE;
    use super::decode_huffman;

    fn huffman_encode(input: &[u8]) -> Vec<u8> {
        let mut bits: u64 = 0;
        let mut bit_count: u32 = 0;
        let mut out = Vec::new();
        for &byte in input {
            let (code, len) = HUFFMAN_TABLE[byte as usize];
            bits = (bits << len) | u64::from(code);
            bit_count += u32::from(len);
            while bit_count >= 8 {
                bit_count -= 8;
                out.push((bits >> bit_count) as u8);
                bits &= (1_u64 << bit_count) - 1;
            }
        }
        if bit_count > 0 {
            let padding = 8 - bit_count;
            bits = (bits << padding) | ((1_u64 << padding) - 1);
            out.push(bits as u8);
        }
        out
    }

    #[test]
    fn huffman_round_trip_typical_header_values() {
        for sample in [
            b"application/octet-stream".as_slice(),
            b"GET".as_slice(),
            b"https".as_slice(),
            b"grpc-encoding".as_slice(),
            b"x-dae-xhttp-mode".as_slice(),
            b"packet-up".as_slice(),
        ] {
            let encoded = huffman_encode(sample);
            let decoded = decode_huffman(&encoded).unwrap();
            assert_eq!(decoded, sample, "round trip for {sample:?}");
        }
    }
}

pub fn semantic_headers_match(decoded: &[HpackHeader], expected: &[(&str, &str)]) -> bool {
    expected.iter().all(|(name, value)| {
        let mut values = decoded
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name.as_bytes()));
        values
            .next()
            .is_some_and(|header| header.value.as_slice() == value.as_bytes())
            && values.next().is_none()
    })
}

#[cfg(test)]
mod semantic_tests {
    use super::{HpackHeader, decode_header_block, semantic_headers_match};

    fn header(name: &str, value: &str) -> HpackHeader {
        HpackHeader {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    #[test]
    fn matches_required_fields_case_insensitive_names() {
        let decoded = vec![
            header(":method", "POST"),
            header(":path", "/hello/Tun"),
            header("Content-Type", "application/grpc"),
        ];
        assert!(semantic_headers_match(
            &decoded,
            &[
                (":method", "POST"),
                (":path", "/hello/Tun"),
                ("content-type", "application/grpc"),
            ]
        ));
        assert!(!semantic_headers_match(
            &decoded,
            &[("content-type", "text/html")]
        ));
        assert!(!semantic_headers_match(
            &decoded,
            &[(":path", "/other/Tun")]
        ));
    }

    #[test]
    fn huffman_encoded_literal_decodes_to_same_semantics() {
        use super::HUFFMAN_TABLE;
        fn huffman_encode(input: &[u8]) -> (Vec<u8>, u8) {
            let mut bits: u64 = 0;
            let mut bit_count: u32 = 0;
            let mut out = Vec::new();
            for &byte in input {
                let (code, len) = HUFFMAN_TABLE[byte as usize];
                bits = (bits << len) | u64::from(code);
                bit_count += u32::from(len);
                while bit_count >= 8 {
                    bit_count -= 8;
                    out.push((bits >> bit_count) as u8);
                    bits &= (1_u64 << bit_count) - 1;
                }
            }
            if bit_count > 0 {
                let padding = 8 - bit_count;
                bits = (bits << padding) | ((1_u64 << padding) - 1);
                out.push(bits as u8);
            }
            let len = out.len() as u8;
            (out, len)
        }
        let (name_bytes, name_len) = huffman_encode(b"test");
        let (value_bytes, value_len) = huffman_encode(b"hello");
        let mut block = vec![0x00];
        block.push(0x80 | name_len);
        block.extend_from_slice(&name_bytes);
        block.push(0x80 | value_len);
        block.extend_from_slice(&value_bytes);
        let decoded = decode_header_block(&block).unwrap();
        assert_eq!(decoded[0].name, b"test");
        assert_eq!(decoded[0].value, b"hello");
    }
}
