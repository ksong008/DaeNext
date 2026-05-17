use crate::SniffingError;

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_HELLO: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME: u8 = 0;
const VERSION_TLS_1_0: [u8; 2] = [0x03, 0x01];
const VERSION_TLS_1_2: [u8; 2] = [0x03, 0x03];

pub fn sniff_tls(data: &[u8]) -> Result<String, SniffingError> {
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
    extract_sni_from_tls(&search[..length])
}

fn extract_sni_from_tls(search: &[u8]) -> Result<String, SniffingError> {
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

fn find_sni_extension(search: &[u8]) -> Result<String, SniffingError> {
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
                    return Ok(sni.trim_end_matches('.').to_owned());
                }
                j += indicator_len;
            }
        }
        i = next;
    }
}
