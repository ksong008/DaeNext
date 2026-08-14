use super::*;

const RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES: usize = 8;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ResidentBoringTlsSessionKey {
    server_name: String,
    ech_config_list_sha256: Option<[u8; 32]>,
}

impl ResidentBoringTlsSessionKey {
    pub(super) fn new(server_name: &str) -> Self {
        Self {
            server_name: normalize_server_name(server_name),
            ech_config_list_sha256: None,
        }
    }

    pub(super) fn with_ech_config_list(server_name: &str, config_list: &[u8]) -> Self {
        use sha2::{Digest, Sha256};

        Self {
            server_name: normalize_server_name(server_name),
            ech_config_list_sha256: Some(Sha256::digest(config_list).into()),
        }
    }
}

fn normalize_server_name(server_name: &str) -> String {
    server_name.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ResidentBoringTlsSessionStats {
    pub(super) entries: usize,
    pub(super) attempted: u64,
    pub(super) reused: u64,
    pub(super) rejected: u64,
    pub(super) stored: u64,
}

impl ResidentBoringTlsSessionStats {
    pub(super) fn merge(&mut self, other: Self) {
        self.entries = self.entries.saturating_add(other.entries);
        self.attempted = self.attempted.saturating_add(other.attempted);
        self.reused = self.reused.saturating_add(other.reused);
        self.rejected = self.rejected.saturating_add(other.rejected);
        self.stored = self.stored.saturating_add(other.stored);
    }
}

pub(super) struct ResidentBoringTlsContextEntry {
    connector: SslConnector,
    sessions: Arc<Mutex<ResidentBoringTlsSessionCache>>,
}

impl fmt::Debug for ResidentBoringTlsContextEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentBoringTlsContextEntry")
            .field("sessions", &self.session_stats())
            .finish_non_exhaustive()
    }
}

impl ResidentBoringTlsContextEntry {
    pub(super) fn build(
        mut builder: SslConnectorBuilder,
        context: &'static str,
    ) -> Result<Self, String> {
        let session_key_index = resident_boring_tls_session_key_index()
            .map_err(|err| format!("allocate {context} BoringSSL session key index: {err}"))?;
        let sessions = Arc::new(Mutex::new(ResidentBoringTlsSessionCache::default()));
        let callback_sessions = Arc::clone(&sessions);
        builder
            .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        builder.set_new_session_callback(move |ssl, session| {
            let Some(key) = ssl.ex_data(session_key_index).cloned() else {
                return;
            };
            callback_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .store(key, session);
        });
        Ok(Self {
            connector: builder.build(),
            sessions,
        })
    }

    pub(super) fn configure(&self) -> Result<ConnectConfiguration, boring::error::ErrorStack> {
        self.connector.configure()
    }

    pub(super) async fn connect<S>(
        &self,
        mut config: ConnectConfiguration,
        session_key: ResidentBoringTlsSessionKey,
        server_name: &str,
        stream: S,
    ) -> Result<tokio_boring::SslStream<S>, ResidentBoringTlsConnectError<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let attempt = self
            .prepare_session(&mut config, session_key)
            .map_err(ResidentBoringTlsConnectError::Session)?;
        match tokio_boring::connect(config, server_name, stream).await {
            Ok(tls) => {
                attempt.complete(tls.ssl().session_reused());
                Ok(tls)
            }
            Err(error) => Err(ResidentBoringTlsConnectError::Handshake(error)),
        }
    }

    fn prepare_session<'a>(
        &'a self,
        config: &mut ConnectConfiguration,
        session_key: ResidentBoringTlsSessionKey,
    ) -> Result<ResidentBoringTlsSessionAttempt<'a>, String> {
        let session_key_index = resident_boring_tls_session_key_index()
            .map_err(|err| format!("read BoringSSL session key index: {err}"))?;
        config.replace_ex_data(session_key_index, session_key.clone());
        let cached = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .begin(&session_key);
        let Some((session, generation)) = cached else {
            return Ok(ResidentBoringTlsSessionAttempt::new(
                self,
                session_key,
                None,
            ));
        };
        // The session came from this entry's callback and therefore from this exact SSL_CTX.
        if let Err(error) = unsafe { config.set_session(&session) } {
            self.reject_session(&session_key, generation);
            return Err(format!("install cached BoringSSL TLS session: {error}"));
        }
        Ok(ResidentBoringTlsSessionAttempt::new(
            self,
            session_key,
            Some(generation),
        ))
    }

    fn record_session_result(
        &self,
        key: &ResidentBoringTlsSessionKey,
        generation: u64,
        reused: bool,
    ) {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_result(key, generation, reused);
    }

    fn reject_session(&self, key: &ResidentBoringTlsSessionKey, generation: u64) {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reject(key, generation);
    }

    pub(super) fn session_stats(&self) -> ResidentBoringTlsSessionStats {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stats()
    }

    pub(super) fn clear_sessions(&self) -> ResidentBoringTlsSessionStats {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear()
    }
}

pub(super) enum ResidentBoringTlsConnectError<S> {
    Session(String),
    Handshake(tokio_boring::HandshakeError<S>),
}

impl<S> ResidentBoringTlsConnectError<S> {
    pub(super) fn handshake_error(&self) -> Option<&tokio_boring::HandshakeError<S>> {
        match self {
            Self::Session(_) => None,
            Self::Handshake(error) => Some(error),
        }
    }
}

impl<S> fmt::Display for ResidentBoringTlsConnectError<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => formatter.write_str(error),
            Self::Handshake(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

struct ResidentBoringTlsSessionAttempt<'a> {
    owner: &'a ResidentBoringTlsContextEntry,
    key: ResidentBoringTlsSessionKey,
    generation: Option<u64>,
    completed: bool,
}

impl<'a> ResidentBoringTlsSessionAttempt<'a> {
    fn new(
        owner: &'a ResidentBoringTlsContextEntry,
        key: ResidentBoringTlsSessionKey,
        generation: Option<u64>,
    ) -> Self {
        Self {
            owner,
            key,
            generation,
            completed: false,
        }
    }

    fn complete(mut self, reused: bool) {
        if let Some(generation) = self.generation {
            self.owner
                .record_session_result(&self.key, generation, reused);
        }
        self.completed = true;
    }
}

impl Drop for ResidentBoringTlsSessionAttempt<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(generation) = self.generation {
            self.owner.reject_session(&self.key, generation);
        }
    }
}

#[derive(Default)]
struct ResidentBoringTlsSessionCache {
    entries: BTreeMap<ResidentBoringTlsSessionKey, ResidentBoringTlsSessionCacheEntry>,
    next_generation: u64,
    attempted: u64,
    reused: u64,
    rejected: u64,
    stored: u64,
}

struct ResidentBoringTlsSessionCacheEntry {
    session: SslSession,
    generation: u64,
}

impl ResidentBoringTlsSessionCache {
    fn begin(&mut self, key: &ResidentBoringTlsSessionKey) -> Option<(SslSession, u64)> {
        let entry = self.entries.get(key)?;
        self.attempted = self.attempted.saturating_add(1);
        Some((entry.session.clone(), entry.generation))
    }

    fn store(&mut self, key: ResidentBoringTlsSessionKey, session: SslSession) {
        let generation = self.touch_generation();
        self.entries.insert(
            key.clone(),
            ResidentBoringTlsSessionCacheEntry {
                session,
                generation,
            },
        );
        self.stored = self.stored.saturating_add(1);
        self.prune_except(&key);
    }

    fn record_result(&mut self, key: &ResidentBoringTlsSessionKey, generation: u64, reused: bool) {
        if reused {
            self.reused = self.reused.saturating_add(1);
            return;
        }
        self.reject(key, generation);
    }

    fn reject(&mut self, key: &ResidentBoringTlsSessionKey, generation: u64) {
        self.rejected = self.rejected.saturating_add(1);
        if self
            .entries
            .get(key)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.entries.remove(key);
        }
    }

    fn touch_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }

    fn prune_except(&mut self, keep: &ResidentBoringTlsSessionKey) {
        if self.entries.len() <= RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES {
            return;
        }
        let mut removable = self
            .entries
            .iter()
            .filter(|(key, _)| *key != keep)
            .map(|(key, entry)| (entry.generation, key.clone()))
            .collect::<Vec<_>>();
        removable.sort_by_key(|(generation, _)| *generation);
        let remove_count = self
            .entries
            .len()
            .saturating_sub(RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES);
        for (_, key) in removable.into_iter().take(remove_count) {
            self.entries.remove(&key);
        }
    }

    fn stats(&self) -> ResidentBoringTlsSessionStats {
        ResidentBoringTlsSessionStats {
            entries: self.entries.len(),
            attempted: self.attempted,
            reused: self.reused,
            rejected: self.rejected,
            stored: self.stored,
        }
    }

    fn clear(&mut self) -> ResidentBoringTlsSessionStats {
        let stats = self.stats();
        self.entries.clear();
        stats
    }
}

fn resident_boring_tls_session_key_index()
-> Result<Index<Ssl, ResidentBoringTlsSessionKey>, boring::error::ErrorStack> {
    static INDEX: OnceLock<Index<Ssl, ResidentBoringTlsSessionKey>> = OnceLock::new();
    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }
    let new_index = Ssl::new_ex_index()?;
    let _ = INDEX.set(new_index);
    Ok(*INDEX
        .get()
        .expect("BoringSSL session key index initialized"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use boring::pkey::{PKey, Private};
    use boring::ssl::{SslAcceptor, SslOptions};
    use boring::x509::X509;
    use rcgen::generate_simple_self_signed;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::*;

    struct TestIdentity {
        certificate: X509,
        private_key: PKey<Private>,
    }

    fn test_identity() -> TestIdentity {
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        TestIdentity {
            certificate: X509::from_der(certified.cert.der().as_ref()).unwrap(),
            private_key: PKey::private_key_from_der(&certified.key_pair.serialize_der()).unwrap(),
        }
    }

    fn tls13_acceptor(identity: &TestIdentity) -> SslAcceptor {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder.set_certificate(&identity.certificate).unwrap();
        builder.set_private_key(&identity.private_key).unwrap();
        builder.check_private_key().unwrap();
        builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
        builder
            .set_session_id_context(b"dae-resident-test")
            .unwrap();
        builder.clear_options(SslOptions::NO_TICKET);
        builder.build()
    }

    fn tls13_context_entry(identity: &TestIdentity) -> ResidentBoringTlsContextEntry {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder
            .cert_store_mut()
            .add_cert(identity.certificate.clone())
            .unwrap();
        ResidentBoringTlsContextEntry::build(builder, "test").unwrap()
    }

    async fn spawn_ticket_server(
        acceptor: SslAcceptor,
        connection_count: usize,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = Arc::new(acceptor);
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..connection_count {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = Arc::clone(&acceptor);
                connections.push(tokio::spawn(async move {
                    let mut tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
                    tls.write_all(b"PING\n").await.unwrap();
                    tls.flush().await.unwrap();
                    let mut buffer = [0; 1];
                    let _ = tls.read(&mut buffer).await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });
        (address, task)
    }

    async fn connect_once(
        entry: &ResidentBoringTlsContextEntry,
        address: std::net::SocketAddr,
        key: ResidentBoringTlsSessionKey,
    ) -> tokio_boring::SslStream<TcpStream> {
        let tcp = TcpStream::connect(address).await.unwrap();
        let config = entry.configure().unwrap();
        entry
            .connect(config, key, "localhost", tcp)
            .await
            .unwrap_or_else(|error| panic!("TLS handshake failed: {error}"))
    }

    #[test]
    fn session_key_partitions_server_name_and_ech_config() {
        let base = ResidentBoringTlsSessionKey::new("EXAMPLE.COM.");
        assert_eq!(base, ResidentBoringTlsSessionKey::new("example.com"));
        assert_ne!(base, ResidentBoringTlsSessionKey::new("other.example"));
        assert_ne!(
            base,
            ResidentBoringTlsSessionKey::with_ech_config_list("example.com", b"ech")
        );
        assert_ne!(
            ResidentBoringTlsSessionKey::with_ech_config_list("example.com", b"first"),
            ResidentBoringTlsSessionKey::with_ech_config_list("example.com", b"second")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_entry_resumes_bounds_and_clears_tls13_sessions() {
        let identity = test_identity();
        let entry = Arc::new(tls13_context_entry(&identity));
        let isolated_entry = tls13_context_entry(&identity);
        let (address, server) = spawn_ticket_server(tls13_acceptor(&identity), 3).await;
        let key = ResidentBoringTlsSessionKey::new("localhost");

        let mut first = connect_once(&entry, address, key.clone()).await;
        assert!(!first.ssl().session_reused());
        let mut payload = [0; 5];
        first.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"PING\n");
        time::timeout(Duration::from_secs(2), async {
            while entry.session_stats().entries == 0 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop(first);

        let second = connect_once(&entry, address, key.clone()).await;
        assert!(second.ssl().session_reused());
        drop(second);

        let isolated = connect_once(&isolated_entry, address, key.clone()).await;
        assert!(!isolated.ssl().session_reused());
        drop(isolated);
        server.await.unwrap();

        let stats = entry.session_stats();
        assert_eq!(stats.attempted, 1);
        assert_eq!(stats.reused, 1);
        assert_eq!(stats.rejected, 0);
        assert!(stats.stored >= 1);

        {
            let mut sessions = entry
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let session = sessions.entries.values().next().unwrap().session.clone();
            for index in 0..RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES + 2 {
                sessions.store(
                    ResidentBoringTlsSessionKey::new(&format!("host-{index}.example")),
                    session.clone(),
                );
            }
            assert_eq!(
                sessions.entries.len(),
                RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES
            );
        }

        let cleared = entry.clear_sessions();
        assert_eq!(
            cleared.entries,
            RESIDENT_BORING_TLS_SESSION_CACHE_MAX_ENTRIES
        );
        assert_eq!(entry.session_stats().entries, 0);
    }
}
