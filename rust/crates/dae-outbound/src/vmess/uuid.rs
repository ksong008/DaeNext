use sha1::{Digest, Sha1};

pub fn normalize_vmess_uuid(input: &str) -> String {
    let len = input.as_bytes().len();
    if !(32..=36).contains(&len) {
        return string_to_uuid5(input);
    }
    input.to_owned()
}

pub fn string_to_uuid5(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update([0_u8; 16]);
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | (5 << 4);
    uuid[8] = (uuid[8] & (0xff >> 2)) | (0x02 << 6);
    format_uuid(&uuid)
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}
