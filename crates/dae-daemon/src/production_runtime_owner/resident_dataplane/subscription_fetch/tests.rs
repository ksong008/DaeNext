use super::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn basic_socks_proxy_fetch_uses_no_transport_owner_and_returns_response() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(serve_http_response(upstream));

        let socks = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let socks_address = socks.local_addr().unwrap();
        let socks_task = tokio::spawn(serve_socks_connect(socks));
        let config = parse_proxy_fetch_config(socks_address);
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let binding = plan.default_proxy_binding().unwrap();
        assert!(ControlTransportOwnerRequirements::from_binding(&binding).is_empty());

        let url = url::Url::parse(&format!("http://{upstream_address}/subscription")).unwrap();
        let request = format!(
            "GET /subscription HTTP/1.1\r\nHost: {upstream_address}\r\nConnection: close\r\n\r\n"
        );
        let response = fetch_http_url_via_default_proxy_async(
            &config,
            &url,
            false,
            request.as_bytes(),
            4_096,
            std::future::pending::<()>(),
        )
        .await
        .unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"fixture-body"));
        upstream_task.await.unwrap();
        socks_task.await.unwrap();
    });
}

fn parse_proxy_fetch_config(socks_address: SocketAddr) -> Config {
    let source = format!(
        r#"
        global {{
            lan_interface: daerust0
        }}
        node {{
            proxy_node: 'socks5://{socks_address}'
        }}
        group {{
            proxy {{
                filter: name(proxy_node)
                policy: fixed(0)
            }}
        }}
        routing {{
            fallback: proxy
        }}
        "#
    );
    let sections = dae_config::parser::parse_config(&source).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}

async fn serve_http_response(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    read_http_head(&mut stream).await;
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nfixture-body",
        )
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
}

async fn serve_socks_connect(listener: TcpListener) {
    let (mut client, _) = listener.accept().await.unwrap();
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting[0], 5);
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&0));
    client.write_all(&[5, 0]).await.unwrap();

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..3], &[5, 1, 0]);
    let target = read_socks_target(&mut client, request[3]).await;
    let mut upstream = TcpStream::connect(target).await.unwrap();
    client
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .unwrap();
}

async fn read_socks_target(stream: &mut TcpStream, address_type: u8) -> String {
    let host = match address_type {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await.unwrap();
            std::net::Ipv4Addr::from(address).to_string()
        }
        3 => {
            let length = stream.read_u8().await.unwrap();
            let mut address = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut address).await.unwrap();
            String::from_utf8(address).unwrap()
        }
        4 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await.unwrap();
            format!("[{}]", std::net::Ipv6Addr::from(address))
        }
        other => panic!("unsupported SOCKS address type {other}"),
    };
    let port = stream.read_u16().await.unwrap();
    format!("{host}:{port}")
}

async fn read_http_head(stream: &mut TcpStream) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
    }
    assert!(request.starts_with(b"GET /subscription HTTP/1.1\r\n"));
}
