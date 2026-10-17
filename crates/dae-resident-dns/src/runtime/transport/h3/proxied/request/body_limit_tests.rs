use super::*;
use crate::runtime::routing::parse_dns_upstream;
use dae_outbound::shared_transport::boring_quic::{
    BoringQuicClientPolicy, build_boring_quic_client_config,
};
use dae_outbound::shared_transport::test_support::{
    boring_quic_client_endpoint, boring_quic_server_config, boring_quic_server_endpoint,
    self_signed_tls_identity,
};
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_and_proxy_doh3_bound_body_and_reject_large_declared_lengths() {
    for proxied in [false, true] {
        for (length, declared) in [
            (65535, None),
            (65536, None),
            (65535, Some(65535)),
            (0, Some(65536)),
        ] {
            let query = build_dns_query_packet(0x1234, "limit.example", 16).unwrap();
            let mut body = query.clone();
            body[0..2].fill(0);
            body[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            body[6..8].copy_from_slice(&1_u16.to_be_bytes());
            body.extend([0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1]);
            if length > 0 {
                let rdata = length - body.len() - 2;
                body.extend((rdata as u16).to_be_bytes());
                body.resize(length, 0);
            }
            let identity = self_signed_tls_identity(&["localhost"]).unwrap();
            let digest: [u8; 32] = Sha256::digest(identity.certificate_der().unwrap()).into();
            let config = boring_quic_server_config(
                &identity,
                &[b"h3".to_vec()],
                Arc::new(quinn::TransportConfig::default()),
            )
            .unwrap();
            let server =
                boring_quic_server_endpoint(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let accepting = server.clone();
            let server_task = tokio::spawn(async move {
                let connection = accepting.accept().await.unwrap().await.unwrap();
                let mut incoming: h3::server::Connection<h3_quinn::Connection, Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                let request = incoming.accept().await.unwrap().unwrap();
                let (_, mut stream) = request.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                let mut headers =
                    http::Response::builder().header(http::header::CONTENT_TYPE, DOH_MEDIA_TYPE);
                if let Some(declared) = declared {
                    headers = headers.header(http::header::CONTENT_LENGTH, declared);
                }
                stream
                    .send_response(headers.body(()).unwrap())
                    .await
                    .unwrap();
                if length > 0 {
                    for chunk in body.chunks(16384) {
                        if stream
                            .send_data(Bytes::copy_from_slice(chunk))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    let _ = stream.finish().await;
                }
                // The declared oversize case sends no DATA and keeps the stream open.
                let _ = incoming.accept().await;
            });
            let policy = BoringQuicClientPolicy::new([b"h3".as_slice()])
                .unwrap()
                .pinned_leaf_sha256(digest, false);
            let config = build_boring_quic_client_config(
                &policy,
                Arc::new(quinn::TransportConfig::default()),
            )
            .unwrap();
            let mut endpoint = boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(config);
            let connection = endpoint
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut driver, mut client) =
                h3::client::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let driver_task = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            let upstream = parse_dns_upstream(
                0,
                "limit",
                "h3://localhost/dns-query",
                server.local_addr().unwrap(),
                0,
            )
            .unwrap();
            let result = if proxied {
                forward_proxied_dns_h3_request(
                    &upstream,
                    &query,
                    &mut client,
                    ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(3)),
                )
                .await
                .map_err(|error| error.to_string())
            } else {
                super::super::super::forward_dns_h3_with_client_async(
                    &upstream,
                    &query,
                    &mut client,
                )
                .await
            };
            if length == 65535 {
                let response = result.unwrap();
                assert_eq!(response.len(), length);
                assert_eq!(&response[..2], &query[..2]);
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.contains("exceeds read limit"),
                    "proxied={proxied} length={length}: {error}"
                );
            }
            connection.close(0_u32.into(), b"DNS body limit test complete");
            endpoint.close(0_u32.into(), b"DNS body limit test complete");
            server.close(0_u32.into(), b"DNS body limit test complete");
            driver_task.abort();
            server_task.abort();
            endpoint.wait_idle().await;
            server.wait_idle().await;
        }
    }
}
