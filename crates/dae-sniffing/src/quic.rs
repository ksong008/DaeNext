use std::collections::BTreeMap;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInPlace;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::SniffingError;
use crate::normalize_domain;
use crate::tls::sniff_tls_client_hello_sni;

const QUIC_V1: u32 = 1;
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_LONG_HEADER_FORM: u8 = 0x80;
const QUIC_FIXED_BIT: u8 = 0x40;
const QUIC_LONG_HEADER_TYPE_MASK: u8 = 0x30;
const QUIC_INITIAL_PACKET_TYPE: u8 = 0;
const QUIC_LONG_HEADER_HP_MASK: u8 = 0x0f;
const QUIC_HP_SAMPLE_LEN: usize = 16;
const QUIC_AEAD_TAG_LEN: usize = 16;
const QUIC_INITIAL_SECRET_LEN: usize = 32;
const QUIC_INITIAL_KEY_LEN: usize = 16;
const QUIC_INITIAL_IV_LEN: usize = 12;

pub(crate) fn sniff_quic_initial_sni(chunks: &[&[u8]]) -> Result<String, SniffingError> {
    let mut crypto = BTreeMap::<u64, Vec<u8>>::new();
    let mut saw_quic = false;
    let mut needs_more = false;

    for chunk in chunks {
        match extract_quic_initial_crypto(chunk, &mut crypto) {
            Ok(found) => saw_quic |= found,
            Err(SniffingError::NeedMore) => needs_more = true,
            Err(SniffingError::NotApplicable | SniffingError::NotFound) => {}
            Err(err) => return Err(err),
        }
    }

    let crypto_stream = assemble_crypto_stream(&crypto)?;
    if crypto_stream.is_empty() {
        return if needs_more {
            Err(SniffingError::NeedMore)
        } else if saw_quic {
            Err(SniffingError::NotFound)
        } else {
            Err(SniffingError::NotApplicable)
        };
    }
    match sniff_tls_client_hello_sni(&crypto_stream) {
        Ok(domain) => Ok(normalize_domain(domain)),
        Err(SniffingError::NeedMore) => Err(SniffingError::NeedMore),
        Err(err) if needs_more => Err(err),
        Err(err) => Err(err),
    }
}

fn extract_quic_initial_crypto(
    datagram: &[u8],
    crypto: &mut BTreeMap<u64, Vec<u8>>,
) -> Result<bool, SniffingError> {
    let mut offset = 0_usize;
    let mut found = false;
    while offset < datagram.len() {
        match decrypt_quic_initial_packet(&datagram[offset..]) {
            Ok(packet) => {
                found = true;
                extract_crypto_frames(&packet.plaintext, crypto)?;
                offset += packet.consumed;
            }
            Err(SniffingError::NotApplicable) if found => break,
            Err(err) => return Err(err),
        }
    }
    Ok(found)
}

struct DecryptedInitialPacket {
    consumed: usize,
    plaintext: Vec<u8>,
}

fn decrypt_quic_initial_packet(packet: &[u8]) -> Result<DecryptedInitialPacket, SniffingError> {
    if packet.len() < 7 {
        return Err(SniffingError::NeedMore);
    }
    let first = packet[0];
    if first & QUIC_LONG_HEADER_FORM == 0 || first & QUIC_FIXED_BIT == 0 {
        return Err(SniffingError::NotApplicable);
    }
    if ((first & QUIC_LONG_HEADER_TYPE_MASK) >> 4) != QUIC_INITIAL_PACKET_TYPE {
        return Err(SniffingError::NotApplicable);
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version != QUIC_V1 {
        return Err(SniffingError::NotApplicable);
    }

    let mut offset = 5_usize;
    let dcid_len = read_u8(packet, &mut offset)? as usize;
    let dcid = read_slice(packet, &mut offset, dcid_len)?;
    let scid_len = read_u8(packet, &mut offset)? as usize;
    let _scid = read_slice(packet, &mut offset, scid_len)?;
    let token_len = read_varint(packet, &mut offset)? as usize;
    let _token = read_slice(packet, &mut offset, token_len)?;
    let packet_len = read_varint(packet, &mut offset)? as usize;
    let pn_offset = offset;
    let packet_end = pn_offset
        .checked_add(packet_len)
        .ok_or(SniffingError::NotApplicable)?;
    if packet_end > packet.len() {
        return Err(SniffingError::NeedMore);
    }
    if packet_len <= QUIC_AEAD_TAG_LEN {
        return Err(SniffingError::NotApplicable);
    }
    // A-10: sample 必须完整位于当前共包 packet 的 packet_end 内；
    // 用 packet.len()（整个 datagram）会在后续共包 packet 存在时
    // 跨越边界取字节，产生错误 mask。
    if pn_offset + 4 + QUIC_HP_SAMPLE_LEN > packet_end {
        return Err(SniffingError::NeedMore);
    }

    let keys = initial_keys(dcid)?;
    let sample = &packet[pn_offset + 4..pn_offset + 4 + QUIC_HP_SAMPLE_LEN];
    let mask = header_protection_mask(&keys.hp, sample)?;
    let unprotected_first = first ^ (mask[0] & QUIC_LONG_HEADER_HP_MASK);
    let pn_len = ((unprotected_first & 0x03) + 1) as usize;
    if pn_len > packet_len || pn_offset + pn_len > packet_end {
        return Err(SniffingError::NotApplicable);
    }
    let mut packet_number = 0_u64;
    let mut pn_bytes = [0_u8; 4];
    for i in 0..pn_len {
        let byte = packet[pn_offset + i] ^ mask[i + 1];
        pn_bytes[i] = byte;
        packet_number = (packet_number << 8) | u64::from(byte);
    }

    let mut header = packet[..pn_offset + pn_len].to_vec();
    header[0] = unprotected_first;
    header[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes[..pn_len]);
    let mut ciphertext = packet[pn_offset + pn_len..packet_end].to_vec();
    let nonce = initial_nonce(&keys.iv, packet_number);
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    cipher
        .decrypt_in_place(GenericArray::from_slice(&nonce), &header, &mut ciphertext)
        .map_err(|_| SniffingError::NotApplicable)?;
    Ok(DecryptedInitialPacket {
        consumed: packet_end,
        plaintext: ciphertext,
    })
}

struct InitialKeys {
    key: [u8; QUIC_INITIAL_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    hp: [u8; QUIC_INITIAL_KEY_LEN],
}

fn initial_keys(dcid: &[u8]) -> Result<InitialKeys, SniffingError> {
    let initial_secret = Hkdf::<Sha256>::new(Some(&QUIC_V1_INITIAL_SALT), dcid);
    let mut client_initial_secret = [0_u8; QUIC_INITIAL_SECRET_LEN];
    hkdf_expand_label(&initial_secret, b"client in", &mut client_initial_secret)?;
    let client_initial = Hkdf::<Sha256>::from_prk(&client_initial_secret)
        .map_err(|_| SniffingError::NotApplicable)?;

    let mut key = [0_u8; QUIC_INITIAL_KEY_LEN];
    let mut iv = [0_u8; QUIC_INITIAL_IV_LEN];
    let mut hp = [0_u8; QUIC_INITIAL_KEY_LEN];
    hkdf_expand_label(&client_initial, b"quic key", &mut key)?;
    hkdf_expand_label(&client_initial, b"quic iv", &mut iv)?;
    hkdf_expand_label(&client_initial, b"quic hp", &mut hp)?;
    Ok(InitialKeys { key, iv, hp })
}

fn hkdf_expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    out: &mut [u8],
) -> Result<(), SniffingError> {
    const TLS13_PREFIX: &[u8] = b"tls13 ";
    let full_label_len = TLS13_PREFIX.len() + label.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(TLS13_PREFIX);
    info.extend_from_slice(label);
    info.push(0);
    hkdf.expand(&info, out)
        .map_err(|_| SniffingError::NotApplicable)
}

fn header_protection_mask(
    hp_key: &[u8; QUIC_INITIAL_KEY_LEN],
    sample: &[u8],
) -> Result<[u8; QUIC_HP_SAMPLE_LEN], SniffingError> {
    if sample.len() != QUIC_HP_SAMPLE_LEN {
        return Err(SniffingError::NeedMore);
    }
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; QUIC_HP_SAMPLE_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}

fn initial_nonce(iv: &[u8; QUIC_INITIAL_IV_LEN], packet_number: u64) -> [u8; QUIC_INITIAL_IV_LEN] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for (dst, src) in nonce[QUIC_INITIAL_IV_LEN - pn.len()..].iter_mut().zip(pn) {
        *dst ^= src;
    }
    nonce
}

fn extract_crypto_frames(
    plaintext: &[u8],
    crypto: &mut BTreeMap<u64, Vec<u8>>,
) -> Result<(), SniffingError> {
    let mut offset = 0_usize;
    while offset < plaintext.len() {
        let frame_type = plaintext[offset];
        offset += 1;
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => skip_ack_frame(plaintext, &mut offset, frame_type == 0x03)?,
            0x06 => {
                let crypto_offset = read_varint(plaintext, &mut offset)?;
                let crypto_len = read_varint(plaintext, &mut offset)? as usize;
                let data = read_slice(plaintext, &mut offset, crypto_len)?;
                crypto.insert(crypto_offset, data.to_vec());
            }
            0x1c | 0x1d => break,
            _ => return Err(SniffingError::NotFound),
        }
    }
    Ok(())
}

fn skip_ack_frame(input: &[u8], offset: &mut usize, has_ecn: bool) -> Result<(), SniffingError> {
    let _largest_ack = read_varint(input, offset)?;
    let _ack_delay = read_varint(input, offset)?;
    let range_count = read_varint(input, offset)?;
    let _first_range = read_varint(input, offset)?;
    for _ in 0..range_count {
        let _gap = read_varint(input, offset)?;
        let _ack_range = read_varint(input, offset)?;
    }
    if has_ecn {
        let _ect0 = read_varint(input, offset)?;
        let _ect1 = read_varint(input, offset)?;
        let _ecn_ce = read_varint(input, offset)?;
    }
    Ok(())
}

fn assemble_crypto_stream(crypto: &BTreeMap<u64, Vec<u8>>) -> Result<Vec<u8>, SniffingError> {
    let mut next_offset = 0_u64;
    let mut out = Vec::new();
    for (offset, data) in crypto {
        if *offset > next_offset {
            return Err(SniffingError::NeedMore);
        }
        let overlap = next_offset.saturating_sub(*offset) as usize;
        if overlap < data.len() {
            out.extend_from_slice(&data[overlap..]);
            next_offset += (data.len() - overlap) as u64;
        }
    }
    Ok(out)
}

fn read_u8(input: &[u8], offset: &mut usize) -> Result<u8, SniffingError> {
    let Some(byte) = input.get(*offset).copied() else {
        return Err(SniffingError::NeedMore);
    };
    *offset += 1;
    Ok(byte)
}

fn read_slice<'a>(
    input: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], SniffingError> {
    let end = offset
        .checked_add(len)
        .ok_or(SniffingError::NotApplicable)?;
    if end > input.len() {
        return Err(SniffingError::NeedMore);
    }
    let slice = &input[*offset..end];
    *offset = end;
    Ok(slice)
}

fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64, SniffingError> {
    let first = read_u8(input, offset)?;
    let len = 1_usize << ((first >> 6) as usize);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(read_u8(input, offset)?);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_initial_sniffer_extracts_client_hello_sni() {
        let packet = test_quic_initial_packet("www.example.com");
        let got = sniff_quic_initial_sni(&[packet.as_slice()]).unwrap();
        assert_eq!(got, "www.example.com");
    }

    #[test]
    fn quic_initial_sniffer_waits_for_split_crypto() {
        let handshake = test_tls_client_hello("www.example.com");
        let first = test_quic_initial_packet_with_crypto(0, &handshake[..20], 0);
        let second = test_quic_initial_packet_with_crypto(20, &handshake[20..], 1);

        assert_eq!(
            sniff_quic_initial_sni(&[first.as_slice()]).unwrap_err(),
            SniffingError::NeedMore
        );
        let got = sniff_quic_initial_sni(&[first.as_slice(), second.as_slice()]).unwrap();
        assert_eq!(got, "www.example.com");
    }

    fn test_quic_initial_packet(host: &str) -> Vec<u8> {
        let handshake = test_tls_client_hello(host);
        test_quic_initial_packet_with_crypto(0, &handshake, 0)
    }

    fn test_quic_initial_packet_with_crypto(
        crypto_offset: u64,
        crypto: &[u8],
        packet_number: u64,
    ) -> Vec<u8> {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let scid = [0x12, 0x34, 0x56, 0x78];
        let mut plaintext = Vec::new();
        plaintext.push(0x06);
        write_varint(crypto_offset, &mut plaintext);
        write_varint(crypto.len() as u64, &mut plaintext);
        plaintext.extend_from_slice(crypto);
        while plaintext.len() < 48 {
            plaintext.push(0);
        }

        let keys = initial_keys(&dcid).unwrap();
        let unprotected_first = QUIC_LONG_HEADER_FORM | QUIC_FIXED_BIT;
        let pn_len = 1_usize;
        let truncated_pn = [(packet_number & 0xff) as u8];
        let packet_len = pn_len + plaintext.len() + QUIC_AEAD_TAG_LEN;
        let mut header = Vec::new();
        header.push(unprotected_first);
        header.extend_from_slice(&QUIC_V1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(&dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(&scid);
        write_varint(0, &mut header);
        write_varint(packet_len as u64, &mut header);
        let pn_offset = header.len();
        header.extend_from_slice(&truncated_pn);

        let nonce = initial_nonce(&keys.iv, packet_number);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
        let mut ciphertext = plaintext;
        cipher
            .encrypt_in_place(GenericArray::from_slice(&nonce), &header, &mut ciphertext)
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let sample_offset = pn_offset + 4;
        let mask =
            header_protection_mask(&keys.hp, &packet[sample_offset..sample_offset + 16]).unwrap();
        packet[0] ^= mask[0] & QUIC_LONG_HEADER_HP_MASK;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[i + 1];
        }
        packet
    }

    fn test_tls_client_hello(host: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let host = host.as_bytes();
        let sni_list_len = 3 + host.len();
        let sni_ext_len = 2 + sni_list_len;
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut out = Vec::new();
        out.push(1);
        let len = body.len() as u32;
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        out.extend_from_slice(&body);
        out
    }

    fn write_varint(value: u64, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.push(0x40 | ((value >> 8) as u8));
            out.push(value as u8);
        } else {
            panic!("test varint too large");
        }
    }
}
