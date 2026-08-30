use super::*;
use boring::ssl::SslRef;
use dae_outbound_stream::shared_transport::reality::reality_client_version;
use foreign_types::ForeignTypeRef;

unsafe extern "C" {
    fn DAE_SSL_set1_reality_config(
        ssl: *mut boring_sys::SSL,
        server_public_key: *const u8,
        server_public_key_len: usize,
        short_id: *const u8,
        short_id_len: usize,
        client_version: *const u8,
    ) -> libc::c_int;

    fn DAE_SSL_get0_reality_auth_key(
        ssl: *const boring_sys::SSL,
        out_key: *mut *const u8,
        out_key_len: *mut usize,
    ) -> libc::c_int;

    fn DAE_SSL_get0_reality_transcript(
        ssl: *const boring_sys::SSL,
        out_client_hello: *mut *const u8,
        out_client_hello_len: *mut usize,
        out_server_hello: *mut *const u8,
        out_server_hello_len: *mut usize,
    ) -> libc::c_int;

}

pub(super) struct RealityBoringTranscript {
    pub(super) client_hello: Vec<u8>,
    pub(super) server_hello: Vec<u8>,
}

pub(super) fn configure_reality_boring_ssl(
    ssl: &mut SslRef,
    verification: &ResidentPeerVerificationPolicy,
) -> Result<(), String> {
    let (public_key, short_id) = verification.reality_material().ok_or_else(|| {
        "VLESS Reality BoringSSL underlay missing typed Reality verification policy".to_owned()
    })?;
    let short_id_ptr = if short_id.is_empty() {
        std::ptr::null()
    } else {
        short_id.as_ptr()
    };
    let client_version = reality_client_version();
    let ok = unsafe {
        DAE_SSL_set1_reality_config(
            ssl.as_ptr(),
            public_key.as_ptr(),
            public_key.len(),
            short_id_ptr,
            short_id.len(),
            client_version.as_ptr(),
        )
    };
    if ok == 1 {
        Ok(())
    } else {
        Err("configure VLESS Reality BoringSSL underlay".to_owned())
    }
}

pub(super) fn reality_boring_auth_key(ssl: &SslRef) -> Option<[u8; 32]> {
    let mut key_ptr = std::ptr::null();
    let mut key_len = 0_usize;
    let ok = unsafe { DAE_SSL_get0_reality_auth_key(ssl.as_ptr(), &mut key_ptr, &mut key_len) };
    if ok != 1 || key_ptr.is_null() || key_len != 32 {
        return None;
    }
    let mut key = [0_u8; 32];
    let source = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    key.copy_from_slice(source);
    Some(key)
}

pub(super) fn reality_boring_transcript(ssl: &SslRef) -> Option<RealityBoringTranscript> {
    let mut client_hello_ptr = std::ptr::null();
    let mut client_hello_len = 0_usize;
    let mut server_hello_ptr = std::ptr::null();
    let mut server_hello_len = 0_usize;
    let ok = unsafe {
        DAE_SSL_get0_reality_transcript(
            ssl.as_ptr(),
            &mut client_hello_ptr,
            &mut client_hello_len,
            &mut server_hello_ptr,
            &mut server_hello_len,
        )
    };
    if ok != 1
        || client_hello_ptr.is_null()
        || client_hello_len < 4
        || server_hello_ptr.is_null()
        || server_hello_len < 4
    {
        return None;
    }
    let client_hello =
        unsafe { std::slice::from_raw_parts(client_hello_ptr, client_hello_len).to_vec() };
    let server_hello =
        unsafe { std::slice::from_raw_parts(server_hello_ptr, server_hello_len).to_vec() };
    Some(RealityBoringTranscript {
        client_hello,
        server_hello,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use boring::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
    use dae_outbound::shared_transport::test_support::self_signed_tls_identity;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    fn handshake_message_has_exact_length(message: &[u8], expected_type: u8) -> bool {
        if message.len() < 4 || message[0] != expected_type {
            return false;
        }
        let body_len = (usize::from(message[1]) << 16)
            | (usize::from(message[2]) << 8)
            | usize::from(message[3]);
        body_len + 4 == message.len()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reality_transcript_getter_returns_exact_serialized_hello_messages() {
        let identity = self_signed_tls_identity(&["localhost"]).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor.set_curves_list("X25519").unwrap();
        acceptor.set_certificate(&identity.certificate).unwrap();
        acceptor.set_private_key(&identity.private_key).unwrap();
        let acceptor = Arc::new(acceptor.build());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio_boring::accept(&acceptor, tcp).await
        });

        let observed = Arc::new(Mutex::new(None));
        let callback_observed = Arc::clone(&observed);
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            *callback_observed.lock().unwrap() = reality_boring_transcript(ssl);
            Ok(())
        });
        let connector = connector.build();
        let mut config = connector.configure().unwrap();
        config.set_verify_hostname(false);
        let reality = ResidentRealityUnderlayPlan {
            public_key: [42; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        };
        let verification = ResidentPeerVerificationPolicy::Reality {
            public_key: reality.public_key,
            short_id: reality.short_id.clone(),
        };
        configure_reality_boring_ssl(&mut config, &verification).unwrap();

        let tcp = TcpStream::connect(address).await.unwrap();
        tokio_boring::connect(config, "localhost", tcp)
            .await
            .unwrap();
        server.await.unwrap().unwrap();

        let transcript = observed.lock().unwrap().take().unwrap();
        assert!(handshake_message_has_exact_length(
            &transcript.client_hello,
            1
        ));
        assert!(handshake_message_has_exact_length(
            &transcript.server_hello,
            2
        ));
    }
}
