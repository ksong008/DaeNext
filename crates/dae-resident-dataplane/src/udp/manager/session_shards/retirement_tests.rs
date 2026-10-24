use super::*;
use crate::udp::tests::tests::test_udp_proxy;

#[tokio::test]
async fn proxy_and_direct_second_retirement_keep_handle_when_reaper_is_full() {
    let admission = Arc::new(ResidentUdpSessionAdmission::new(Some(2)));
    let peer = "127.0.0.1:12345".parse().unwrap();
    let dst = "192.0.2.1:12345".parse().unwrap();
    let proxy = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    });
    let proxy_key = UdpSessionKey::new(&proxy, peer, dst);
    let direct_key = UdpDirectSessionKey::new(peer, dst, 0);
    let mut reaper = UdpSessionReaper::new(1);
    let mut proxies = HashMap::new();
    let mut directs = HashMap::new();
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    proxies.insert(
        proxy_key.clone(),
        ResidentUdpProxyShardEntry {
            actor_id: 1,
            session: UdpSessionEntry {
                sender,
                handle: tokio::spawn(std::future::pending()),
            },
            _admission: admission.try_acquire().unwrap(),
        },
    );
    assert!(retire_proxy_session(&proxy_key, &mut proxies, &mut reaper));
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let handle = tokio::spawn(std::future::pending());
    let abort = handle.abort_handle();
    directs.insert(
        direct_key.clone(),
        ResidentUdpDirectShardEntry {
            actor_id: 2,
            session: UdpDirectSessionEntry { sender, handle },
            _admission: admission.try_acquire().unwrap(),
        },
    );
    assert!(!retire_direct_session(
        &direct_key,
        &mut directs,
        &mut reaper
    ));
    assert_eq!(directs.len(), 1);
    assert!(!abort.is_finished());
    reaper.join_until_deadline(time::Instant::now()).await;
    assert!(retire_direct_session(
        &direct_key,
        &mut directs,
        &mut reaper
    ));
    reaper.join_until_deadline(time::Instant::now()).await;
    assert!(abort.is_finished());
    assert_eq!(admission.current(), 0);

    // Mirror the order so both retirement paths hit capacity exhaustion.
    reaper.retire(tokio::spawn(std::future::pending())).unwrap();
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let handle = tokio::spawn(async {
        panic!("finished actor panic");
    });
    let abort = handle.abort_handle();
    proxies.insert(
        proxy_key.clone(),
        ResidentUdpProxyShardEntry {
            actor_id: 3,
            session: UdpSessionEntry { sender, handle },
            _admission: admission.try_acquire().unwrap(),
        },
    );
    while !abort.is_finished() {
        tokio::task::yield_now().await;
    }
    reconcile_finished_proxy_sessions(&mut proxies, &mut reaper);
    assert_eq!(proxies.len(), 1);
    assert!(!retire_proxy_session(&proxy_key, &mut proxies, &mut reaper));
    reaper.join_until_deadline(time::Instant::now()).await;
    reconcile_finished_proxy_sessions(&mut proxies, &mut reaper);
    assert_eq!(reaper.join_next().await, Some(true));
    assert!(proxies.is_empty());
    assert_eq!(admission.current(), 0);
}
