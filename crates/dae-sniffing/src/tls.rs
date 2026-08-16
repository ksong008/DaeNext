use crate::SniffingError;

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_HELLO: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME: u8 = 0;
const VERSION_TLS_1_0: [u8; 2] = [0x03, 0x01];
const VERSION_TLS_1_2: [u8; 2] = [0x03, 0x03];

pub fn sniff_tls(data: &[u8]) -> Result<String, SniffingError> {
    sniff_tls_sni(data).map(str::to_owned)
}

pub fn sniff_tls_sni(data: &[u8]) -> Result<&str, SniffingError> {
    if data.len() < 5 {
        return Err(SniffingError::NotApplicable);
    }
    if data[0] != CONTENT_TYPE_HANDSHAKE
        || (data[1..3] != VERSION_TLS_1_0 && data[1..3] != VERSION_TLS_1_2)
    {
        return Err(SniffingError::NotApplicable);
    }

    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    let search = &data[5..];
    if search.len() < length {
        return Err(SniffingError::NeedMore);
    }
    sniff_tls_client_hello_sni(&search[..length])
}

pub(crate) fn sniff_tls_client_hello_sni(search: &[u8]) -> Result<&str, SniffingError> {
    if search.len() < 4 {
        return Err(SniffingError::NeedMore);
    }
    if search[0] != HANDSHAKE_TYPE_HELLO {
        return Err(SniffingError::NotApplicable);
    }
    let length = ((search[1] as usize) << 16) + ((search[2] as usize) << 8) + search[3] as usize;
    if search.len() < length + 4 {
        return Err(SniffingError::NeedMore);
    }
    extract_sni_from_tls(&search[..length + 4])
}

fn extract_sni_from_tls(search: &[u8]) -> Result<&str, SniffingError> {
    let mut boundary = 39_usize;
    if search.len() < boundary {
        return Err(SniffingError::NotApplicable);
    }
    if search[0] != HANDSHAKE_TYPE_HELLO {
        return Err(SniffingError::NotApplicable);
    }

    let length2 = ((search[1] as usize) << 16) + ((search[2] as usize) << 8) + search[3] as usize;
    if search.len() > length2 + 4 {
        return Err(SniffingError::NotApplicable);
    }
    if search[4..6] != VERSION_TLS_1_2 {
        return Err(SniffingError::NotApplicable);
    }

    let session_id_length = search[boundary - 1] as usize;
    boundary += session_id_length + 2;
    if search.len() < boundary {
        return Err(SniffingError::NotApplicable);
    }

    let cipher_suite_length =
        u16::from_be_bytes([search[boundary - 2], search[boundary - 1]]) as usize;
    boundary += cipher_suite_length + 1;
    if search.len() < boundary {
        return Err(SniffingError::NotApplicable);
    }

    let compress_methods_length = search[boundary - 1] as usize;
    boundary += compress_methods_length + 2;
    if search.len() < boundary {
        return Err(SniffingError::NotApplicable);
    }

    let extensions_length =
        u16::from_be_bytes([search[boundary - 2], search[boundary - 1]]) as usize;
    boundary += extensions_length;
    if search.len() < boundary {
        return Err(SniffingError::NotApplicable);
    }

    find_sni_extension(&search[boundary - extensions_length..boundary])
}

fn find_sni_extension(search: &[u8]) -> Result<&str, SniffingError> {
    let mut i = 0_usize;
    loop {
        if i + 4 >= search.len() {
            return Err(SniffingError::NotFound);
        }
        let typ = u16::from_be_bytes([search[i], search[i + 1]]);
        let ext_length = u16::from_be_bytes([search[i + 2], search[i + 3]]) as usize;
        let next = i + 4 + ext_length;
        if next > search.len() {
            return Err(SniffingError::NotApplicable);
        }
        if typ == TLS_EXTENSION_SERVER_NAME {
            if i + 6 > search.len() {
                return Err(SniffingError::NotApplicable);
            }
            let sni_len = u16::from_be_bytes([search[i + 4], search[i + 5]]) as usize;
            if ext_length < sni_len + 2 {
                return Err(SniffingError::NotApplicable);
            }
            let mut j = i + 6;
            while j + 3 <= next {
                let indicator_len = u16::from_be_bytes([search[j + 1], search[j + 2]]) as usize;
                if search[j] == TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME {
                    if j + 3 + indicator_len > next {
                        return Err(SniffingError::NotApplicable);
                    }
                    let sni = std::str::from_utf8(&search[j + 3..j + 3 + indicator_len])
                        .map_err(|_| SniffingError::NotApplicable)?;
                    return Ok(sni.trim_end_matches('.'));
                }
                // Skip the entry's 3-byte header (1 type + 2 length) plus its
                // value. Advancing past the header is mandatory even for a
                // zero-length non-host_name entry: with `j += indicator_len`
                // alone, `j` would never move (3 + 0 > 0) and `j + 3 <= next`
                // would stay true forever (CPU-spin DoS, client-controlled).
                j += 3 + indicator_len;
            }
        }
        i = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full TLS record carrying a ClientHello whose SNI extension
    /// contains exactly `entries` (each `(type, name)`), mirroring the wire
    /// path a real client-controlled packet takes into `sniff_tls_sni`.
    fn build_client_hello_sni(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (ty, name) in entries {
            list.push(ty[0]);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name);
        }
        let list_len = list.len();

        let mut ext = Vec::new();
        ext.extend_from_slice(&TLS_EXTENSION_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_HELLO);
        handshake.extend_from_slice(&[0, 0, 0]); // body length, patched below
        handshake.extend_from_slice(&VERSION_TLS_1_2);
        handshake.extend_from_slice(&[0xAA; 32]); // random
        handshake.push(0); // session id length
        handshake.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        handshake.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        handshake.push(1); // compression methods length
        handshake.push(0x00); // null compression
        handshake.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&ext);

        let body_len = handshake.len() - 4;
        handshake[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&VERSION_TLS_1_2);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Regression test: a zero-length SNI entry whose type is not host_name
    /// must not stall the parser (previously `j += indicator_len` never moved
    /// `j`, so `j + 3 <= next` stayed true forever). The function must return
    /// normally and still find a subsequent host_name entry.
    #[test]
    fn sni_zero_length_non_host_entry_does_not_hang_and_host_is_found() {
        let data = build_client_hello_sni(&[(&[0x01], &[]), (&[0x00], b"example.com")]);
        let got = sniff_tls_sni(&data).unwrap();
        assert_eq!(got, "example.com");
    }

    #[test]
    fn sni_host_name_first_still_works() {
        let data = build_client_hello_sni(&[(&[0x00], b"example.com")]);
        assert_eq!(sniff_tls_sni(&data).unwrap(), "example.com");
    }

    /// A non-host_name entry carrying payload must be skipped by its full
    /// 3-byte header plus value length, so the next entry is not misaligned.
    #[test]
    fn sni_non_host_entry_with_payload_does_not_misalign() {
        let data = build_client_hello_sni(&[(&[0x01], b"deadbeef"), (&[0x00], b"example.org")]);
        assert_eq!(sniff_tls_sni(&data).unwrap(), "example.org");
    }
}
