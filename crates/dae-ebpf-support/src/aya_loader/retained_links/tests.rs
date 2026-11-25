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
fn stale_netlink_recovery_requires_the_program_pinned_for_the_slot() {
    let Some(mut stale) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let ns = Namespace::new();
    ns.iface("owned0");
    let mut spec = spec(&ns, "owned0");
    spec.program_name = "tproxy_lan_ingress_l2".to_owned();
    spec.priority = 2;
    spec.handle = crate::tc_handle(0x2023, 4);
    let mut host_spec = spec.clone();
    host_spec.target.netns = None;
    let stale_root = stale.report.map_pin_path.clone().unwrap();
    let mut unreserved = host_spec.clone();
    unreserved.priority = 1;
    for backend in [AttachBackend::TcNetlink, AttachBackend::Tcx] {
        let error = with_optional_netns(Some(&ns.0), || {
            load_attach_aya_sched_classifier_with_recovery(
                &mut stale,
                &unreserved,
                backend,
                Some(&stale_root),
            )
        })
        .unwrap_err();
        assert!(error.contains("requires a reserved host slot"), "{error}");
        assert!(!stale_root.join("tc-recovery").exists());
        assert_eq!(stale.pending_attachment_count(), 0);
    }
    let attach = |loaded: &mut AyaUserspaceLoadedObject, root: &Path| {
        with_optional_netns(Some(&ns.0), || {
            load_attach_aya_sched_classifier_with_recovery(
                loaded,
                &host_spec,
                AttachBackend::TcNetlink,
                Some(root),
            )
        })
        .unwrap()
    };
    let query = || query_aya_tc_netlink_binding(&spec.target, spec.priority, spec.handle).unwrap();
    let recover = |handle, owners: &[StaleTcOwner<'_>]| {
        detach_stale_aya_tc_filter(
            &spec.target,
            spec.priority,
            handle,
            owners,
            &spec.program_name,
            Some(1),
        )
    };
    let stale_owner = || StaleTcOwner {
        pin_root: &stale_root,
        pid: 99,
    };

    let report = attach(&mut stale, &stale_root);
    let (ifindex, old) = query();
    assert_eq!(old.as_ref().map(|(id, _)| *id), report.program_id);
    let pinned = SchedClassifier::from_pin(stale_root.join("tc-recovery").join(format!(
        "{ifindex}-ingress-{}-{:08x}",
        spec.priority, spec.handle,
    )))
    .unwrap();
    let info = pinned.info().unwrap();
    assert_eq!(
        info.name_as_str(),
        Some(crate::truncated_bpf_name(&spec.program_name))
    );
    assert_ne!(info.name_as_str(), Some(spec.program_name.as_str()));

    assert!(
        recover(spec.handle, &[])
            .unwrap_err()
            .contains("unverified")
    );
    recover(spec.handle + 1, &[stale_owner()]).unwrap();
    assert_eq!(query().1, old);
    recover(spec.handle, &[stale_owner()]).unwrap();
    assert!(query().1.is_none());
    recover(spec.handle, &[stale_owner()]).unwrap();
    stale.cleanup_retained_links(None).unwrap();

    let mut replacement =
        super::super::listener_lifecycle_tests::loaded_with_timeout(None).unwrap();
    let replacement_root = replacement.report.map_pin_path.clone().unwrap();
    let replacement_report = attach(&mut replacement, &replacement_root);
    assert_eq!(report.program_name, replacement_report.program_name);
    assert_eq!(report.program_tag, replacement_report.program_tag);
    assert_ne!(report.program_id, replacement_report.program_id);
    let foreign = query().1.unwrap();
    assert!(
        recover(spec.handle, &[stale_owner()])
            .unwrap_err()
            .contains("foreign")
    );
    assert_eq!(query().1, Some(foreign));
    recover(
        spec.handle,
        &[
            stale_owner(),
            StaleTcOwner {
                pin_root: &replacement_root,
                pid: 99,
            },
        ],
    )
    .unwrap();
    replacement.cleanup_retained_links(None).unwrap();
    assert!(query().1.is_none());
}

#[test]
fn loaded_object_exercises_legacy_recovery_for_all_host_roles_without_program_pins() {
    let Some(mut loaded) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let ns = Namespace::new();
    ns.iface("owned0");
    let root = loaded.report.map_pin_path.clone().unwrap();
    let owner = |pid| StaleTcOwner {
        pin_root: &root,
        pid,
    };
    for (role, direction) in [
        ("lan_ingress", TcAttachDirection::Ingress),
        ("lan_egress", TcAttachDirection::Egress),
        ("wan_ingress", TcAttachDirection::Ingress),
        ("wan_egress", TcAttachDirection::Egress),
    ] {
        for layer in ["l2", "l3"] {
            let mut spec = spec(&ns, "owned0");
            spec.target.direction = direction;
            spec.program_name = format!("tproxy_{role}_{layer}");
            load_attach_aya_sched_classifier(&mut loaded, &spec, AttachBackend::TcNetlink).unwrap();
            let expected_name = format!("tproxy_{role}_l2");
            let filter = || {
                query_aya_tc_netlink_binding(&spec.target, spec.priority, spec.handle)
                    .unwrap()
                    .1
            };
            let recover = |pid, dae0_ifindex, name| {
                detach_stale_aya_tc_filter(
                    &spec.target,
                    spec.priority,
                    spec.handle,
                    &[owner(pid)],
                    name,
                    dae0_ifindex,
                )
            };
            assert!(!root.join("tc-recovery").exists());
            let before = filter().unwrap();
            assert!(recover(100, Some(1), &expected_name).is_err());
            assert!(recover(99, Some(2), &expected_name).is_err());
            assert!(recover(99, Some(1), "foreign_l2").is_err());
            assert_eq!(filter(), Some(before));
            recover(99, Some(1), &expected_name)
                .unwrap_or_else(|error| panic!("{role}/{layer}: {error}"));
            assert!(filter().is_none());
            loaded.cleanup_retained_links(None).unwrap();
        }
    }
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
