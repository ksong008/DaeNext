use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use boring::error::ErrorStack;
use boring::ssl::{SslContext, SslContextBuilder};
use boring::x509::X509;
use boring::x509::store::{X509Store, X509StoreBuilder};
use foreign_types::ForeignType;
use sha2::{Digest, Sha256};

pub const SYSTEM_CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

type CachedSystemCaSnapshot = Option<Result<Arc<SystemCaSnapshot>, SystemCaError>>;

static SYSTEM_CA_SNAPSHOT: OnceLock<Mutex<CachedSystemCaSnapshot>> = OnceLock::new();

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SystemCaIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub certificate_count: usize,
}

pub struct SystemCaSnapshot {
    identity: SystemCaIdentity,
    boring_store: X509Store,
}

impl SystemCaSnapshot {
    pub fn identity(&self) -> &SystemCaIdentity {
        &self.identity
    }

    pub fn boring_store(&self) -> X509Store {
        self.boring_store.clone()
    }

    pub fn install_boring_builder(&self, builder: &mut SslContextBuilder) {
        builder.set_cert_store_ref(&self.boring_store);
    }

    pub fn install_boring_context(&self, context: &mut SslContext) -> Result<(), SystemCaError> {
        let up_ref_result = unsafe { boring_sys::X509_STORE_up_ref(self.boring_store.as_ptr()) };
        if up_ref_result != 1 {
            return Err(SystemCaError::BoringStore {
                message: ErrorStack::get().to_string(),
            });
        }
        unsafe {
            boring_sys::SSL_CTX_set_cert_store(context.as_ptr(), self.boring_store.as_ptr());
        }
        Ok(())
    }

    fn load_from_environment() -> Result<Self, SystemCaError> {
        let explicit = env::var_os("SSL_CERT_FILE").filter(|value| !value.is_empty());
        let candidates = SYSTEM_CA_BUNDLE_PATHS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let path = select_bundle_path(explicit.as_deref(), &candidates)?;
        Self::load_from_path(path)
    }

    pub(crate) fn load_from_path(path: PathBuf) -> Result<Self, SystemCaError> {
        let bytes = fs::read(&path).map_err(|error| SystemCaError::Read {
            path: path.clone(),
            message: error.to_string(),
        })?;
        if bytes.is_empty() {
            return Err(SystemCaError::Empty { path });
        }

        let certificates = X509::stack_from_pem(&bytes).map_err(|error| SystemCaError::Parse {
            path: path.clone(),
            message: error.to_string(),
        })?;
        if certificates.is_empty() {
            return Err(SystemCaError::NoUsableCertificates { path });
        }

        let mut boring_builder =
            X509StoreBuilder::new().map_err(|error| SystemCaError::BoringStore {
                message: error.to_string(),
            })?;
        let mut unique_der = HashSet::new();

        for certificate in certificates {
            let der = certificate.to_der().map_err(|error| SystemCaError::Parse {
                path: path.clone(),
                message: error.to_string(),
            })?;
            if !unique_der.insert(der.clone()) {
                continue;
            }
            boring_builder
                .add_cert(&certificate)
                .map_err(|error| SystemCaError::BoringStore {
                    message: error.to_string(),
                })?;
        }

        let certificate_count = unique_der.len();
        if certificate_count == 0 {
            return Err(SystemCaError::NoUsableCertificates { path });
        }
        let sha256 = encode_hex(Sha256::digest(&bytes).as_ref());

        Ok(Self {
            identity: SystemCaIdentity {
                path,
                sha256,
                certificate_count,
            },
            boring_store: boring_builder.build(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemCaError {
    ExplicitPathMissing { path: PathBuf },
    NoBundleFound { candidates: Vec<PathBuf> },
    Read { path: PathBuf, message: String },
    Empty { path: PathBuf },
    Parse { path: PathBuf, message: String },
    NoUsableCertificates { path: PathBuf },
    BoringStore { message: String },
    CachePoisoned,
}

impl fmt::Display for SystemCaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExplicitPathMissing { path } => write!(
                formatter,
                "SSL_CERT_FILE does not name a regular CA bundle file: {}",
                path.display()
            ),
            Self::NoBundleFound { candidates } => write!(
                formatter,
                "no system CA bundle found in {}",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Read { path, message } => {
                write!(
                    formatter,
                    "read system CA bundle {}: {message}",
                    path.display()
                )
            }
            Self::Empty { path } => {
                write!(formatter, "system CA bundle is empty: {}", path.display())
            }
            Self::Parse { path, message } => write!(
                formatter,
                "parse system CA bundle {}: {message}",
                path.display()
            ),
            Self::NoUsableCertificates { path } => write!(
                formatter,
                "system CA bundle contains no usable certificates: {}",
                path.display()
            ),
            Self::BoringStore { message } => {
                write!(formatter, "build BoringSSL system CA store: {message}")
            }
            Self::CachePoisoned => formatter.write_str("system CA snapshot cache lock poisoned"),
        }
    }
}

impl std::error::Error for SystemCaError {}

pub fn system_ca_snapshot() -> Result<Arc<SystemCaSnapshot>, SystemCaError> {
    let cache = SYSTEM_CA_SNAPSHOT.get_or_init(|| Mutex::new(None));
    cached_system_ca_snapshot(cache, SystemCaSnapshot::load_from_environment)
}

fn cached_system_ca_snapshot(
    cache: &Mutex<CachedSystemCaSnapshot>,
    load: impl FnOnce() -> Result<SystemCaSnapshot, SystemCaError>,
) -> Result<Arc<SystemCaSnapshot>, SystemCaError> {
    let mut cache = cache.lock().map_err(|_| SystemCaError::CachePoisoned)?;
    if let Some(snapshot) = cache.as_ref() {
        return snapshot.clone();
    }
    let snapshot = load().map(Arc::new);
    *cache = Some(snapshot.clone());
    snapshot
}

pub fn invalidate_system_ca_snapshot() -> Result<bool, SystemCaError> {
    let cache = SYSTEM_CA_SNAPSHOT.get_or_init(|| Mutex::new(None));
    invalidate_cached_system_ca_snapshot(cache)
}

fn invalidate_cached_system_ca_snapshot(
    cache: &Mutex<CachedSystemCaSnapshot>,
) -> Result<bool, SystemCaError> {
    let mut cache = cache.lock().map_err(|_| SystemCaError::CachePoisoned)?;
    Ok(cache.take().is_some())
}

fn select_bundle_path(
    explicit: Option<&OsStr>,
    candidates: &[PathBuf],
) -> Result<PathBuf, SystemCaError> {
    if let Some(explicit) = explicit {
        let path = PathBuf::from(explicit);
        return path
            .is_file()
            .then_some(path.clone())
            .ok_or(SystemCaError::ExplicitPathMissing { path });
    }
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .ok_or_else(|| SystemCaError::NoBundleFound {
            candidates: candidates.to_vec(),
        })
}

fn encode_hex(bytes: &[u8]) -> String {
    use fmt::Write;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_transport::test_support::{
        TestCertificateValidity, signed_tls_certificate_chain,
    };
    use boring::stack::Stack;
    use boring::x509::X509StoreContext;
    use foreign_types::ForeignTypeRef;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "daenext-system-ca-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CertificateChain {
        root_pem: String,
        leaf_der: Vec<u8>,
    }

    impl CertificateChain {
        fn signed(server_name: &str) -> Self {
            Self::signed_with_validity(server_name, true)
        }

        fn expired(server_name: &str) -> Self {
            Self::signed_with_validity(server_name, false)
        }

        fn signed_with_validity(server_name: &str, current: bool) -> Self {
            let validity = if current {
                TestCertificateValidity::Current
            } else {
                TestCertificateValidity::Expired
            };
            let material = signed_tls_certificate_chain(server_name, validity).unwrap();
            Self {
                root_pem: String::from_utf8(material.root_pem().unwrap()).unwrap(),
                leaf_der: material.leaf_identity.certificate_der().unwrap(),
            }
        }
    }

    fn ca_pem() -> String {
        let material = signed_tls_certificate_chain(
            "root-only.system-ca.test",
            TestCertificateValidity::Current,
        )
        .unwrap();
        String::from_utf8(material.root_pem().unwrap()).unwrap()
    }

    fn boring_verification(
        snapshot: &SystemCaSnapshot,
        chain: &CertificateChain,
        host: &str,
    ) -> Result<(), String> {
        let certificate = X509::from_der(&chain.leaf_der).unwrap();
        let intermediates = Stack::new().unwrap();
        let mut context = X509StoreContext::new().unwrap();
        let mut verification_error = None;
        let verified = context
            .init(
                &snapshot.boring_store,
                &certificate,
                &intermediates,
                |context| {
                    context.verify_param_mut().set_host(host)?;
                    let verified = context.verify_cert()?;
                    if !verified {
                        verification_error = Some(format!(
                            "{:?} at certificate depth {}",
                            context.verify_result(),
                            context.error_depth()
                        ));
                    }
                    Ok(verified)
                },
            )
            .map_err(|error| error.to_string())?;
        if verified {
            Ok(())
        } else {
            Err(verification_error.unwrap_or_else(|| "certificate verification failed".to_owned()))
        }
    }

    #[test]
    fn explicit_path_is_authoritative() {
        let directory = TestDirectory::new("explicit");
        let explicit = directory.path("explicit.pem");
        let fallback = directory.path("fallback.pem");
        fs::write(&explicit, ca_pem()).unwrap();
        fs::write(&fallback, ca_pem()).unwrap();

        let selected = select_bundle_path(Some(explicit.as_os_str()), &[fallback]).unwrap();
        assert_eq!(selected, explicit);
    }

    #[test]
    fn invalid_explicit_path_does_not_fall_back() {
        let directory = TestDirectory::new("invalid-explicit");
        let explicit = directory.path("missing.pem");
        let fallback = directory.path("fallback.pem");
        fs::write(&fallback, ca_pem()).unwrap();

        assert_eq!(
            select_bundle_path(Some(explicit.as_os_str()), &[fallback]),
            Err(SystemCaError::ExplicitPathMissing { path: explicit })
        );
    }

    #[test]
    fn candidates_use_fixed_order() {
        let directory = TestDirectory::new("order");
        let first = directory.path("first.pem");
        let second = directory.path("second.pem");
        fs::write(&first, ca_pem()).unwrap();
        fs::write(&second, ca_pem()).unwrap();

        assert_eq!(
            select_bundle_path(None, &[first.clone(), second]).unwrap(),
            first
        );
    }

    #[test]
    fn valid_bundle_builds_boringssl_store_and_identity() {
        let directory = TestDirectory::new("valid");
        let path = directory.path("roots.pem");
        let pem = ca_pem();
        fs::write(&path, &pem).unwrap();

        let snapshot = SystemCaSnapshot::load_from_path(path.clone()).unwrap();
        assert_eq!(snapshot.identity().path, path);
        assert_eq!(snapshot.identity().certificate_count, 1);
        assert_eq!(
            snapshot.identity().sha256,
            encode_hex(Sha256::digest(pem.as_bytes()).as_ref())
        );
        let mut builder =
            boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        snapshot.install_boring_builder(&mut builder);
        let context = builder.build();
        assert_eq!(
            context.cert_store().as_ptr(),
            snapshot.boring_store.as_ptr()
        );
    }

    #[test]
    fn boringssl_enforces_trust_validity_and_hostname_contract() {
        const SERVER_NAME: &str = "trusted.system-ca.test";

        let directory = TestDirectory::new("provider-contract");
        let path = directory.path("roots.pem");
        let trusted = CertificateChain::signed(SERVER_NAME);
        let unknown = CertificateChain::signed(SERVER_NAME);
        let expired = CertificateChain::expired(SERVER_NAME);
        fs::write(&path, format!("{}{}", trusted.root_pem, expired.root_pem)).unwrap();
        let snapshot = SystemCaSnapshot::load_from_path(path).unwrap();

        assert_eq!(
            boring_verification(&snapshot, &trusted, SERVER_NAME),
            Ok(())
        );
        assert!(boring_verification(&snapshot, &unknown, SERVER_NAME).is_err());
        assert!(boring_verification(&snapshot, &expired, SERVER_NAME).is_err());
        assert!(boring_verification(&snapshot, &trusted, "wrong.system-ca.test").is_err());
    }

    #[test]
    fn duplicate_certificates_do_not_inflate_effective_count() {
        let directory = TestDirectory::new("duplicates");
        let path = directory.path("roots.pem");
        let pem = ca_pem();
        fs::write(&path, format!("{pem}{pem}")).unwrap();

        let snapshot = SystemCaSnapshot::load_from_path(path).unwrap();
        assert_eq!(snapshot.identity().certificate_count, 1);
    }

    #[test]
    fn install_boring_context_replaces_its_certificate_store() {
        let directory = TestDirectory::new("boring-context");
        let path = directory.path("roots.pem");
        fs::write(&path, ca_pem()).unwrap();
        let snapshot = SystemCaSnapshot::load_from_path(path).unwrap();
        let mut context = SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .unwrap()
            .build();

        snapshot.install_boring_context(&mut context).unwrap();
        assert_eq!(
            context.cert_store().as_ptr(),
            snapshot.boring_store.as_ptr()
        );
    }

    #[test]
    fn cache_invalidation_rereads_bundle_without_invalidating_old_snapshot() {
        let directory = TestDirectory::new("cache-reload");
        let path = directory.path("roots.pem");
        fs::write(&path, ca_pem()).unwrap();
        let cache = Mutex::new(None);

        let first =
            cached_system_ca_snapshot(&cache, || SystemCaSnapshot::load_from_path(path.clone()))
                .unwrap();
        let first_hash = first.identity().sha256.clone();
        fs::write(&path, ca_pem()).unwrap();
        let cached =
            cached_system_ca_snapshot(&cache, || SystemCaSnapshot::load_from_path(path.clone()))
                .unwrap();
        assert!(Arc::ptr_eq(&first, &cached));

        assert!(invalidate_cached_system_ca_snapshot(&cache).unwrap());
        let reloaded =
            cached_system_ca_snapshot(&cache, || SystemCaSnapshot::load_from_path(path.clone()))
                .unwrap();
        assert_ne!(reloaded.identity().sha256, first_hash);
        assert_eq!(first.identity().sha256, first_hash);
    }

    #[test]
    fn empty_and_damaged_bundles_fail_closed() {
        let directory = TestDirectory::new("invalid");
        let empty = directory.path("empty.pem");
        let damaged = directory.path("damaged.pem");
        fs::write(&empty, []).unwrap();
        fs::write(&damaged, b"not a PEM certificate").unwrap();

        assert!(matches!(
            SystemCaSnapshot::load_from_path(empty.clone()),
            Err(SystemCaError::Empty { path }) if path == empty
        ));
        assert!(matches!(
            SystemCaSnapshot::load_from_path(damaged.clone()),
            Err(SystemCaError::Parse { path, .. }) | Err(SystemCaError::NoUsableCertificates { path })
                if path == damaged
        ));
    }

    #[test]
    fn missing_candidates_fail_closed() {
        let directory = TestDirectory::new("missing");
        let candidates = vec![directory.path("one.pem"), directory.path("two.pem")];
        assert_eq!(
            select_bundle_path(None, &candidates),
            Err(SystemCaError::NoBundleFound { candidates })
        );
    }
}
