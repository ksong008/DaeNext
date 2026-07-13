use sha2::{Digest, Sha256};

use super::*;

pub(super) fn connect_udp_authentication_identity(
    authentication: &ResidentConnectUdpAuthPlan,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match authentication {
        ResidentConnectUdpAuthPlan::None => hasher.update(b"none"),
        ResidentConnectUdpAuthPlan::Basic { username, password } => {
            hasher.update(b"basic\0");
            hasher.update((username.len() as u64).to_be_bytes());
            hasher.update(username.as_bytes());
            hasher.update((password.len() as u64).to_be_bytes());
            hasher.update(password.as_bytes());
        }
    }
    hasher.finalize().into()
}
