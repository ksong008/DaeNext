use sha2::{Digest, Sha256};

use dae_resident_model::{ResidentProxyBinding, ResidentProxyProtocolPlan};

pub fn resident_transport_binding_identity_digest(
    domain: &[u8],
    binding: &ResidentProxyBinding,
) -> [u8; 32] {
    type Cached = (
        std::sync::Weak<dae_resident_model::ResidentProxyPlan>,
        Vec<u8>,
        u32,
        [u8; 32],
    );
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<Cached>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(std::sync::Mutex::default);
    {
        let mut entries = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = entries.iter().position(|(plan, prefix, mark, _)| {
            prefix == domain
                && *mark == binding.effective_socket_mark()
                && plan
                    .upgrade()
                    .is_some_and(|plan| std::sync::Arc::ptr_eq(&plan, binding.shared_plan()))
        }) && let Some(entry) = entries.remove(index)
        {
            let digest = entry.3;
            entries.push_back(entry);
            return digest;
        }
    }
    let mut digest = Sha256::new();
    digest.update(domain);
    update_binding_identity(&mut digest, binding);
    let digest = digest.finalize().into();
    if domain.len() <= 1024 {
        let mut entries = cache.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= 128 {
            entries.pop_front();
        }
        entries.push_back((
            std::sync::Arc::downgrade(binding.shared_plan()),
            domain.to_vec(),
            binding.effective_socket_mark(),
            digest,
        ));
    }
    digest
}

fn update_identity_part(digest: &mut Sha256, field: &[u8], value: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn update_binding_identity(digest: &mut Sha256, binding: &ResidentProxyBinding) {
    let proxy = binding.plan();
    let effective_mark = binding.effective_socket_mark();
    update_identity_part(digest, b"proxy", b"begin");
    update_identity_part(digest, b"graph-link-hash", proxy.graph_link_hash.as_bytes());
    update_identity_part(digest, b"server-host", proxy.server_host.as_bytes());
    update_identity_part(digest, b"server-port", &proxy.server_port.to_be_bytes());
    update_identity_part(digest, b"server-name", proxy.server_name.as_bytes());
    update_identity_part(digest, b"stream-host", proxy.stream_host.as_bytes());
    update_identity_part(digest, b"stream-path", proxy.stream_path.as_bytes());
    update_identity_part(
        digest,
        b"grpc-mode",
        proxy.grpc_mode.link_value().as_bytes(),
    );
    update_identity_part(digest, b"tls", proxy.tls.as_bytes());
    update_identity_part(digest, b"mark", &effective_mark.to_be_bytes());
    update_identity_part(digest, b"mptcp", &[u8::from(proxy.mptcp)]);
    update_identity_part(digest, b"allow-insecure", &[u8::from(proxy.allow_insecure)]);
    update_identity_part(
        digest,
        b"alpn-count",
        &(proxy.alpn.len() as u64).to_be_bytes(),
    );
    for alpn in &proxy.alpn {
        update_identity_part(digest, b"alpn", alpn.as_bytes());
    }
    if let ResidentProxyProtocolPlan::JuicityQuicTcp { congestion, .. } = &proxy.handler {
        update_identity_part(
            digest,
            b"juicity-congestion-control",
            congestion.as_str().as_bytes(),
        );
    }
    if let ResidentProxyProtocolPlan::TuicQuicTcp {
        congestion,
        udp_relay_mode,
        ..
    } = &proxy.handler
    {
        update_identity_part(
            digest,
            b"tuic-congestion-control",
            congestion.as_str().as_bytes(),
        );
        update_identity_part(
            digest,
            b"tuic-udp-relay-mode",
            udp_relay_mode.as_str().as_bytes(),
        );
    }
    update_identity_part(
        digest,
        b"tls-fragment-present",
        &[u8::from(proxy.tls_fragment.is_some())],
    );
    if let Some(fragment) = proxy.tls_fragment.as_ref() {
        update_identity_part(
            digest,
            b"fragment-min-length",
            &fragment.min_length().to_be_bytes(),
        );
        update_identity_part(
            digest,
            b"fragment-max-length",
            &fragment.max_length().to_be_bytes(),
        );
        update_identity_part(
            digest,
            b"fragment-min-interval",
            &fragment.min_interval_ms().to_be_bytes(),
        );
        update_identity_part(
            digest,
            b"fragment-max-interval",
            &fragment.max_interval_ms().to_be_bytes(),
        );
    }
    update_identity_part(
        digest,
        b"fingerprint-present",
        &[u8::from(proxy.utls_fingerprint.is_some())],
    );
    if let Some(fingerprint) = proxy.utls_fingerprint.as_ref() {
        update_identity_part(digest, b"fp-source", fingerprint.source.as_bytes());
        update_identity_part(digest, b"fp-requested", fingerprint.requested.as_bytes());
        update_identity_part(digest, b"fp-name", fingerprint.name.as_bytes());
        update_identity_part(digest, b"fp-canonical", fingerprint.canonical.as_bytes());
        update_identity_part(digest, b"fp-family", fingerprint.family.as_bytes());
        update_identity_part(digest, b"fp-client", fingerprint.client.as_bytes());
        update_identity_part(
            digest,
            b"fp-randomized",
            &[u8::from(fingerprint.randomized)],
        );
        update_identity_part(
            digest,
            b"fp-alpn-policy",
            fingerprint.alpn_policy.as_bytes(),
        );
        update_identity_part(
            digest,
            b"fp-default-alpn-count",
            &(fingerprint.default_alpn.len() as u64).to_be_bytes(),
        );
        for alpn in &fingerprint.default_alpn {
            update_identity_part(digest, b"fp-default-alpn", alpn.as_bytes());
        }
    }
    update_identity_part(digest, b"ech-present", &[u8::from(proxy.ech.is_some())]);
    if let Some(ech) = proxy.ech.as_ref() {
        update_identity_part(digest, b"ech-config-list-sha256", ech.config_list_sha256());
    }
    update_identity_part(
        digest,
        b"reality-present",
        &[u8::from(proxy.reality.is_some())],
    );
    if let Some(reality) = proxy.reality.as_ref() {
        update_identity_part(digest, b"reality-public-key", &reality.public_key);
        update_identity_part(digest, b"reality-short-id", &reality.short_id);
        update_identity_part(digest, b"reality-spider-x", reality.spider_x.as_bytes());
        update_identity_part(
            digest,
            b"reality-mldsa65-present",
            &[u8::from(reality.mldsa65_verify.is_some())],
        );
        if let Some(mldsa65_verify) = reality.mldsa65_verify.as_ref() {
            update_identity_part(digest, b"reality-mldsa65-sha256", mldsa65_verify.sha256());
        }
    }
    let parent = binding
        .chain_parent()
        .expect("published resident proxy chain execution must be materialized");
    update_identity_part(digest, b"parent-present", &[u8::from(parent.is_some())]);
    if let Some(parent) = parent.as_ref() {
        update_binding_identity(digest, parent);
    }
    update_identity_part(digest, b"proxy", b"end");
}
