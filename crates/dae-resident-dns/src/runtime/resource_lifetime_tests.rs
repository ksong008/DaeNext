use super::*;
use std::time::Duration;

#[tokio::test]
async fn dns_pool_retirement_waits_for_tcp_consumer_then_joins_terminal_cleanup() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; size as usize];
        stream.read_exact(&mut query).await.unwrap();
        let packet = DnsPacketView::parse(&query).unwrap();
        let reply = build_reject_response(&query, &packet).unwrap();
        stream.write_u16(reply.len() as u16).await.unwrap();
        stream.write_all(&reply).await.unwrap();
        // The actor's terminal shutdown must close its peer as well.
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let plan = Arc::new(ResidentDnsPlan::asis(0));
    let stop = ResidentStopSignal::shared();
    let (root, task) = plan.resource_owner(Arc::clone(&stop)).unwrap();
    let resolver = ResidentDnsResolver::new(Arc::clone(&plan)).with_resource_lease(root.clone());
    let owner = tokio::spawn(task);
    drop(root);
    assert!(!plan.forwarders.closing.load(Ordering::Acquire));
    let request = build_dns_query_packet(123, "lease.example", DNS_QTYPE_A).unwrap();
    let reply = resolver.query_tcp(target, &request).await.unwrap();
    assert_eq!(&reply[..2], &request[..2]);
    assert!(!owner.is_finished());
    drop(resolver);
    let report = time::timeout(Duration::from_secs(2), owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report["status"], "pass", "{report}");
    assert!(plan.forwarders.closing.load(Ordering::Acquire));
    server.await.unwrap();
}

#[tokio::test]
async fn explicit_runtime_stop_closes_dns_resources_even_with_live_tcp_lease() {
    let plan = Arc::new(ResidentDnsPlan::asis(0));
    let stop = ResidentStopSignal::shared();
    let (lease, task) = plan.resource_owner(Arc::clone(&stop)).unwrap();
    let owner = tokio::spawn(task);
    stop.store(true, Ordering::Release);
    let report = time::timeout(Duration::from_secs(2), owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report["status"], "pass");
    assert!(plan.forwarders.closing.load(Ordering::Acquire));
    drop(lease);
}
