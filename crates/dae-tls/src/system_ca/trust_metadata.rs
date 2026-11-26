use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_ANCHOR_WIRE_BYTES: usize = 4096;

#[derive(Default)]
pub(super) struct TrustMetadata {
    pub(super) requested_x509_ids: Vec<u8>,
    pub(super) individual_x509_ids: Vec<u8>,
    pub(super) mtc: Vec<u8>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(default)]
    groups: Vec<Group>,
    mtc: Option<Mtc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    id: String,
    members: Vec<Member>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    id: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mtc {
    valid_from_unix: u64,
    expires_unix: u64,
    logs: Vec<Log>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Log {
    log_id: String,
    advertised_ids: Vec<String>,
    subtrees: Vec<Subtree>,
    revoked_serials: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subtree {
    start: u64,
    end: u64,
    sha256: String,
}

pub(super) fn read(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_file() {
        return Err("expected a regular trust metadata file".to_owned());
    }
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err("trust metadata exceeds 256 KiB".to_owned());
    }
    Ok(bytes)
}

impl TrustMetadata {
    pub(super) fn from_bundle(
        bytes: Option<&[u8]>,
        trusted: &HashSet<[u8; 32]>,
    ) -> Result<Self, String> {
        let manifest: Manifest = match bytes {
            Some(bytes) => serde_json::from_slice(bytes).map_err(|err| err.to_string())?,
            None => Manifest::default(),
        };
        let mut members: BTreeMap<Vec<u8>, [u8; 32]> = super::CHROME_152_TRUST_ANCHORS
            .iter()
            .map(|(digest, id)| (id.to_vec(), **digest))
            .collect();
        // Preserve the existing Chrome order for the built-in set.
        let mut individual: Vec<Vec<u8>> = super::CHROME_152_TRUST_ANCHORS
            .iter()
            .filter(|(digest, _)| trusted.contains(*digest))
            .map(|(_, id)| id.to_vec())
            .collect();
        let mut groups = BTreeMap::new();
        if manifest.groups.len() > 32 {
            return Err("at most 32 trust anchor groups can be configured".to_owned());
        }
        for group in manifest.groups {
            let id = encode_relative_oid(&group.id)?;
            if group.members.is_empty() || group.members.len() > 256 || groups.contains_key(&id) {
                return Err("invalid or duplicate trust anchor group".to_owned());
            }
            let mut trusted_members = Vec::new();
            let mut group_members = BTreeSet::new();
            for member in group.members {
                let member_id = encode_relative_oid(&member.id)?;
                let digest = parse_digest(&member.sha256)?;
                if !group_members.insert(member_id.clone())
                    || members
                        .insert(member_id.clone(), digest)
                        .is_some_and(|previous| previous != digest)
                {
                    return Err("duplicate member or conflicting trust anchor ID".to_owned());
                }
                if trusted.contains(&digest) {
                    if !individual.contains(&member_id) {
                        individual.push(member_id.clone());
                    }
                    trusted_members.push(member_id);
                }
            }
            groups.insert(id, (trusted_members, group_members.len()));
        }
        let mut covered = BTreeSet::new();
        let mut requested = Vec::new();
        for (id, (trusted_members, total)) in &groups {
            if members.contains_key(id) {
                return Err("trust anchor group ID duplicates a certificate ID".to_owned());
            }
            if trusted_members.len() == *total {
                append_id(&mut requested, id)?;
                covered.extend(trusted_members.iter());
            }
        }
        let mut individual_x509_ids = Vec::new();
        for id in &individual {
            append_id(&mut individual_x509_ids, id)?;
            if !covered.contains(id) {
                append_id(&mut requested, id)?;
            }
        }
        let mtc = manifest
            .mtc
            .map(|mtc| mtc.encode(&members, &groups))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            requested_x509_ids: requested,
            individual_x509_ids,
            mtc,
        })
    }
}

impl Mtc {
    fn encode<T>(
        self,
        members: &BTreeMap<Vec<u8>, [u8; 32]>,
        groups: &BTreeMap<Vec<u8>, T>,
    ) -> Result<Vec<u8>, String> {
        if self.valid_from_unix >= self.expires_unix
            || self.expires_unix > i64::MAX as u64
            || self.logs.is_empty()
            || self.logs.len() > 32
        {
            return Err("invalid MTC metadata validity or log count".to_owned());
        }
        let mut ids = Vec::new();
        let mut logs = Vec::new();
        let mut seen_log_ids = BTreeSet::new();
        let mut seen_advertised_ids = BTreeSet::new();
        for mut log in self.logs {
            let log_id = encode_relative_oid(&log.log_id)?;
            if !seen_log_ids.insert(log_id.clone())
                || log.advertised_ids.is_empty()
                || log.subtrees.is_empty()
                || log.subtrees.len() > 1365
                || log.revoked_serials.len() > 8191
            {
                return Err("invalid or duplicate MTC log".to_owned());
            }
            for advertised in log.advertised_ids {
                let id = encode_relative_oid(&advertised)?;
                if members.contains_key(&id)
                    || groups.contains_key(&id)
                    || !seen_advertised_ids.insert(id.clone())
                {
                    return Err("duplicate MTC advertisement ID".to_owned());
                }
                append_id(&mut ids, &id)?;
            }
            logs.push(log_id.len() as u8);
            logs.extend_from_slice(&log_id);
            log.subtrees.sort_by_key(|tree| (tree.start, tree.end));
            if log
                .subtrees
                .windows(2)
                .any(|pair| (pair[0].start, pair[0].end) == (pair[1].start, pair[1].end))
            {
                return Err("duplicate MTC subtree".to_owned());
            }
            logs.extend_from_slice(&((48 * log.subtrees.len()) as u16).to_be_bytes());
            for subtree in log.subtrees {
                let start = subtree.start;
                let Some(size) = subtree.end.checked_sub(start) else {
                    return Err("inverted MTC subtree range".to_owned());
                };
                if size == 0 || (start != 0 && size > (1 << start.trailing_zeros())) {
                    return Err("invalid MTC subtree range".to_owned());
                }
                logs.extend_from_slice(&subtree.start.to_be_bytes());
                logs.extend_from_slice(&subtree.end.to_be_bytes());
                logs.extend_from_slice(&parse_digest(&subtree.sha256)?);
            }
            log.revoked_serials.sort_unstable();
            log.revoked_serials.dedup();
            logs.extend_from_slice(&((8 * log.revoked_serials.len()) as u16).to_be_bytes());
            for serial in log.revoked_serials {
                logs.extend_from_slice(&serial.to_be_bytes());
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_unix.to_be_bytes());
        out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
        out.extend_from_slice(&ids);
        out.extend_from_slice(&logs);
        Ok(out)
    }
}

fn append_id(out: &mut Vec<u8>, id: &[u8]) -> Result<(), String> {
    if out.len() + id.len() + 1 > MAX_ANCHOR_WIRE_BYTES {
        return Err("trust anchor list exceeds the wire budget".to_owned());
    }
    out.push(id.len() as u8);
    out.extend_from_slice(id);
    Ok(())
}

fn encode_relative_oid(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for component in text.split('.') {
        if component.is_empty()
            || !component.bytes().all(|byte| byte.is_ascii_digit())
            || (component.len() > 1 && component.starts_with('0'))
        {
            return Err("expected a canonical dotted relative OID".to_owned());
        }
        let mut value: u64 = component
            .parse()
            .map_err(|_| "relative OID component exceeds u64")?;
        let mut encoded = [0; 10];
        let mut start = encoded.len() - 1;
        encoded[start] = (value & 0x7f) as u8;
        while value > 0x7f {
            value >>= 7;
            start -= 1;
            encoded[start] = (value & 0x7f) as u8 | 0x80;
        }
        out.extend_from_slice(&encoded[start..]);
        if out.len() > 255 {
            return Err("relative OID exceeds 255 bytes".to_owned());
        }
    }
    Ok(out)
}

fn parse_digest(text: &str) -> Result<[u8; 32], String> {
    let mut digest = [0; 32];
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected a 64-character SHA-256 digest".to_owned());
    }
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("ASCII hex pair");
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn group_replaces_members_only_when_all_are_trusted() {
        let metadata = serde_json::to_vec(&json!({
            "groups": [{
                "id": "80.1",
                "members": [
                    {"id": "50", "sha256": "11".repeat(32)},
                    {"id": "51", "sha256": "22".repeat(32)}
                ]
            }]
        }))
        .unwrap();
        let both =
            TrustMetadata::from_bundle(Some(&metadata), &HashSet::from([[0x11; 32], [0x22; 32]]))
                .unwrap();
        assert_eq!(both.requested_x509_ids, [2, 80, 1]);
        assert_eq!(both.individual_x509_ids, [1, 50, 1, 51]);
        let partial =
            TrustMetadata::from_bundle(Some(&metadata), &HashSet::from([[0x11; 32]])).unwrap();
        assert_eq!(partial.requested_x509_ids, [1, 50]);
        assert_eq!(partial.individual_x509_ids, [1, 50]);
    }

    #[test]
    fn rejects_ambiguity_in_anchor_ids() {
        assert_eq!(
            encode_relative_oid("32473.1").unwrap(),
            [0x81, 0xfd, 0x59, 1]
        );
        for malformed in ["", ".1", "1.", "01.2", "18446744073709551616", "1.-2"] {
            assert!(encode_relative_oid(malformed).is_err(), "{malformed}");
        }
        for group_id in ["50", "80.1"] {
            let metadata = serde_json::to_vec(&json!({
                "groups": [
                    {"id": group_id, "members": [{"id": "50", "sha256": "11".repeat(32)}]},
                    {"id": "80.2", "members": [{"id": "50", "sha256": "22".repeat(32)}]}
                ]
            }))
            .unwrap();
            assert!(TrustMetadata::from_bundle(Some(&metadata), &HashSet::new()).is_err());
        }
    }
}
