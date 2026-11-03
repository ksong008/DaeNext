use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

fn command(args: &[&str]) -> String {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

struct Namespace(String);
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).output();
    }
}

#[test]
fn retained_peer_detaches_before_its_namespace_is_deleted() {
    let Some(mut loaded) = super::super::listener_lifecycle_tests::loaded_with_timeout(None) else {
        return;
    };
    let original = fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
    for backend in [AttachBackend::TcNetlink, AttachBackend::Tcx] {
        let ns = Namespace(format!("dae-retained-{}", std::process::id()));
        command(&["ip", "netns", "add", &ns.0]);
        command(&[
            "ip", "-n", &ns.0, "link", "add", "peer0", "type", "veth", "peer", "name", "peer1",
        ]);
        command(&["ip", "-n", &ns.0, "link", "set", "peer0", "up"]);
        let spec = crate::TcBpfAttachSpec::new(
            crate::TcAttachTarget::netns(&ns.0, "peer0", TcAttachDirection::Ingress),
            "0",
            "unused",
            "classifier/dae0peer_ingress",
        )
        .native_attach_spec("tproxy_dae0peer_ingress", 0, crate::tc_handle(0x2022, 2));
        let report = load_attach_aya_sched_classifier(&mut loaded, &spec, backend).unwrap();
        assert_eq!(report.backend, backend);
        let filters = || {
            command(&[
                "ip", "netns", "exec", &ns.0, "tc", "filter", "show", "dev", "peer0", "ingress",
            ])
        };
        if backend == AttachBackend::TcNetlink {
            assert!(filters().contains("tproxy_dae0peer"));
        }
        unload_aya_sched_classifier_in_netns(&mut loaded, "tproxy_dae0peer_ingress", Some(&ns.0))
            .unwrap();
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            original
        );
        assert!(
            !filters().contains("tproxy_dae0peer"),
            "retained filter survived unload in the target netns"
        );
        assert!(
            Path::new("/run/netns").join(&ns.0).exists(),
            "cleanup must be verified before namespace deletion"
        );
        // Losing the named mount must not lose the cleanup namespace. Retain
        // an fd, attach again, remove the name and still detach in that owner.
        load_attach_aya_sched_classifier(&mut loaded, &spec, backend).unwrap();
        let retained = fs::File::open(Path::new("/run/netns").join(&ns.0)).unwrap();
        command(&["ip", "netns", "del", &ns.0]);
        let path = format!("/proc/thread-self/fd/{}", retained.as_raw_fd());
        let retained_filters = || {
            with_optional_netns(Some(&path), || {
                Ok(command(&[
                    "tc", "filter", "show", "dev", "peer0", "ingress",
                ]))
            })
            .unwrap()
        };
        if backend == AttachBackend::TcNetlink {
            assert!(retained_filters().contains("tproxy_dae0peer"));
        }
        unload_aya_sched_classifier_in_netns(&mut loaded, "tproxy_dae0peer_ingress", Some(&path))
            .unwrap();
        assert!(!retained_filters().contains("tproxy_dae0peer"));
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            original
        );
        drop(retained);
        drop(ns);
    }
}
