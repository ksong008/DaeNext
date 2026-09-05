use std::fmt::{self, Write};
use std::hash::Hash;

// Compatibility export: the shared value type has a single owner.
pub use dae_core_types::OwnerGeneration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactedIdentityError {
    EmptyNamespace,
    InvalidNamespace,
}

impl fmt::Display for RedactedIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNamespace => formatter.write_str("owner identity namespace is empty"),
            Self::InvalidNamespace => {
                formatter.write_str("owner identity namespace contains an invalid character")
            }
        }
    }
}

impl std::error::Error for RedactedIdentityError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RedactedOwnerIdentity {
    namespace: &'static str,
    fingerprint: [u8; 32],
}

impl RedactedOwnerIdentity {
    pub fn new(
        namespace: &'static str,
        fingerprint: [u8; 32],
    ) -> Result<Self, RedactedIdentityError> {
        if namespace.is_empty() {
            return Err(RedactedIdentityError::EmptyNamespace);
        }
        if !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RedactedIdentityError::InvalidNamespace);
        }
        Ok(Self {
            namespace,
            fingerprint,
        })
    }

    pub const fn namespace(&self) -> &'static str {
        self.namespace
    }

    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub fn report_value(&self) -> String {
        let mut value =
            String::with_capacity(self.namespace.len() + 1 + self.fingerprint.len() * 2);
        value.push_str(self.namespace);
        value.push(':');
        for byte in self.fingerprint {
            let _ = write!(&mut value, "{byte:02x}");
        }
        value
    }
}

pub trait PhysicalOwnerKey: Clone + Eq + Hash + Send + Sync + 'static {
    fn redacted_identity(&self) -> RedactedOwnerIdentity;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PhysicalOwnerKeyProjection<K: PhysicalOwnerKey> {
    generation: OwnerGeneration,
    key: K,
}

impl<K: PhysicalOwnerKey> PhysicalOwnerKeyProjection<K> {
    pub fn new(generation: OwnerGeneration, key: K) -> Self {
        Self { generation, key }
    }

    pub const fn generation(&self) -> OwnerGeneration {
        self.generation
    }

    pub const fn key(&self) -> &K {
        &self.key
    }

    pub fn redacted_identity(&self) -> RedactedOwnerIdentity {
        self.key.redacted_identity()
    }
}
