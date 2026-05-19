use super::*;

pub fn vmess_cmd_key_from_uuid(uuid: &str) -> Result<[u8; 16], OutboundError> {
    let uuid = normalize_vmess_uuid(uuid);
    let uuid_bytes = parse_uuid_bytes(&uuid)?;
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, uuid_bytes);
    Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}
