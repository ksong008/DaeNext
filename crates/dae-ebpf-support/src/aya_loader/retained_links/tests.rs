use super::*;
use std::process::Command;

fn command(args: &[&str]) {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
struct Namespace(String);
impl Namespace {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let name = format!(
            "dae-clean-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        command(&["ip", "netns", "add", &name]);
        Self(name)
    }
    fn iface(&self, name: &str) {
        command(&["ip", "-n", &self.0, "link", "add", name, "type", "dummy"]);
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).output();
    }
}
fn spec(ns: &Namespace, iface: &str) -> TcNativeAttachSpec {
    crate::TcBpfAttachSpec::new(
        crate::TcAttachTarget::netns(&ns.0, iface, TcAttachDirection::Ingress),
        "1",
        "unused",
        "classifier/dae0peer_ingress",
    )
    .native_attach_spec("tproxy_dae0peer_ingress", 1, crate::tc_handle(0x2022, 2))
}
fn original_ns() -> u64 {
    fs::metadata("/proc/thread-self/ns/net").unwrap().ino()
}

#[test]
fn pending_namespace_failure_does_not_skip_other_links_and_can_retry() {
    let Some(mut loaded) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let original = original_ns();
    for backend in [AttachBackend::TcNetlink, AttachBackend::Tcx] {
        let ns = Namespace::new();
        ns.iface("pending0");
        ns.iface("ready0");
        load_attach_aya_sched_classifier(
            &mut loaded,
            &spec(&ns, "pending0"),
            AttachBackend::TcNetlink,
        )
        .unwrap();
        load_attach_aya_sched_classifier(&mut loaded, &spec(&ns, "ready0"), backend).unwrap();
        let Attachment::Tc { netns, .. } = &mut loaded.attachments[0].attachment else {
            unreachable!()
        };
        let correct = mem::replace(netns, fs::File::open("/dev/null").unwrap());
        for _ in 0..3 {
            let error = loaded.cleanup_retained_links(None).unwrap_err();
            assert!(error.contains("enter target netns"), "{error}");
            assert_eq!(loaded.pending_attachment_count(), 1);
            assert_eq!(original_ns(), original);
        }
        let Attachment::Tc { netns, .. } = &mut loaded.attachments[0].attachment else {
            unreachable!()
        };
        *netns = correct;
        command(&["ip", "netns", "del", &ns.0]);
        loaded.cleanup_retained_links(None).unwrap();
        assert_eq!(loaded.pending_attachment_count(), 0);
        assert_eq!(original_ns(), original);
    }
}

#[test]
fn consumed_netlink_detach_error_recovers_from_exact_identity() {
    let Some(mut loaded) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let ns = Namespace::new();
    ns.iface("owned0");
    let wrong = Namespace::new(); // only loopback, no matching ifindex
    load_attach_aya_sched_classifier(&mut loaded, &spec(&ns, "owned0"), AttachBackend::TcNetlink)
        .unwrap();
    let Attachment::Tc { link, .. } = &mut loaded.attachments[0].attachment else {
        unreachable!()
    };
    let consumed = link.take().unwrap();
    let error = with_optional_netns(Some(&wrong.0), || {
        consumed.detach().map_err(|e| e.to_string())
    })
    .unwrap_err();
    eprintln!("actual consuming Aya detach failed in empty namespace: {error}");
    loaded.cleanup_retained_links(None).unwrap();
    assert_eq!(loaded.pending_attachment_count(), 0);
    with_optional_netns(Some(&ns.0), || {
        let ifindex = super::super::tc_attach::current_netns_interface_index("owned0")?;
        assert_eq!(
            super::super::tc_netlink_query::filter_program_id(
                &super::super::tc_netlink_query::FilterLocation {
                    ifindex,
                    parent: u32::from(TcHandle::from(TcAttachType::Ingress)),
                    priority: 1,
                    handle: crate::tc_handle(0x2022, 2),
                }
            )?,
            None
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn same_location_replacement_is_never_deleted_by_the_old_owner() {
    let Some(mut loaded) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let mut foreign = super::super::listener_lifecycle_tests::loaded_with_timeout(None).unwrap();
    let ns = Namespace::new();
    ns.iface("owned0");
    load_attach_aya_sched_classifier(&mut loaded, &spec(&ns, "owned0"), AttachBackend::TcNetlink)
        .unwrap();
    let Attachment::Tc { link, .. } = &mut loaded.attachments[0].attachment else {
        unreachable!()
    };
    let previous = link.take().unwrap();
    let classifier: &mut SchedClassifier = foreign
        .ebpf
        .program_mut("tproxy_dae0peer_ingress")
        .unwrap()
        .try_into()
        .unwrap();
    classifier.load().unwrap();
    let id = classifier.info().unwrap().id();
    let replacement = with_optional_netns(Some(&ns.0), || {
        classifier
            .attach_to_link(previous)
            .map_err(|e| e.to_string())
    })
    .unwrap();
    for _ in 0..3 {
        let error = loaded.cleanup_retained_links(None).unwrap_err();
        assert!(error.contains("foreign filter"), "{error}");
        assert!(error.contains(&format!("observed {id}")));
        assert_eq!(loaded.pending_attachment_count(), 1);
    }
    with_optional_netns(Some(&ns.0), || {
        classifier.detach(replacement).map_err(|e| e.to_string())
    })
    .unwrap();
    loaded.cleanup_retained_links(None).unwrap();
    assert_eq!(loaded.pending_attachment_count(), 0);
}
