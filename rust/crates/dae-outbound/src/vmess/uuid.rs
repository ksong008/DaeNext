use sha1::{Digest, Sha1};

pub fn normalize_vmess_uuid(input: &str) -> String {
    let len = input.as_bytes().len();
    if !(32..=36).contains(&len) {
        return string_to_uuid5(input);
    }
    input.to_owned()
}

pub fn string_to_uuid5(input: &str) -> String {
    format_uuid(&string_to_uuid5_bytes(input))
}

pub fn string_to_uuid5_bytes(input: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update([0_u8; 16]);
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | (5 << 4);
    uuid[8] = (uuid[8] & (0xff >> 2)) | (0x02 << 6);
    uuid
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (index, byte) in uuid.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
