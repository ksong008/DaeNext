use super::*;
use crate::plan::{build_resident_dataplane_plan, build_resident_proxy_plan_for_node};
use crate::transport_identity::resident_transport_binding_identity_digest;
use dae_runtime_control::OwnerGeneration;

const BINDING_IDENTITY_TEST_DOMAIN: &[u8] = b"dae/binding-identity-test/v1";

fn fixture_plan() -> Arc<ResidentProxyPlan> {
    let source = r#"
        global {
            lan_interface: daerust0
            allow_insecure: true
            so_mark_from_dae: 1234
        }
        node {
            socks_binding: 'socks5://binding-user:binding-secret@binding.fixture.invalid:28001'
        }
        group {
            proxy {
                filter: name(socks_binding)
                policy: fixed(0)
            }
        }
        routing {
            fallback: proxy
        }
    "#;
    let sections = dae_config::parser::parse_config(source).expect("parse binding fixture");
    let config = dae_config::schema::build_config(&sections).expect("build binding fixture");
    let plan = build_resident_dataplane_plan(&config).expect("materialize binding fixture");
    Arc::clone(
        plan.default_proxy_group()
            .expect("binding fixture group")
            .snapshot_candidate()
            .expect("binding fixture candidate")
            .binding
            .shared_plan(),
    )
}

fn chain_fixture(source: &str) -> ResidentProxyPlan {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
            lan_interface: daerust0
            allow_insecure: true
            so_mark_from_dae: 1234
        }
        routing {
            fallback: direct
        }
        "#,
    )
    .expect("parse binding chain fixture");
    let config = dae_config::schema::build_config(&sections).expect("build binding chain fixture");
    build_resident_proxy_plan_for_node(
        &config,
        "binding-chain".to_owned(),
        "binding-chain-node".to_owned(),
        source.to_owned(),
    )
    .expect("materialize binding chain fixture")
}

fn set_chain_marks(plan: &mut ResidentProxyPlan, marks: &[u32]) {
    let (root_mark, parent_marks) = marks
        .split_first()
        .expect("binding chain fixture requires a root mark");
    plan.mark = *root_mark;
    let mut current = plan.chain_parent.as_mut();
    for mark in parent_marks {
        let parent = current.expect("binding chain fixture parent mark");
        let parent = Arc::make_mut(parent);
        parent.mark = *mark;
        current = parent.chain_parent.as_mut();
    }
    assert!(current.is_none(), "binding chain fixture mark count");
}

#[test]
fn binding_clone_shares_the_materialized_plan() {
    let plan = fixture_plan();
    let binding = ResidentProxyBinding::resident(Arc::clone(&plan), OwnerGeneration::new(47))
        .expect("resident binding");
    let cloned = binding.clone();

    assert!(Arc::ptr_eq(binding.shared_plan(), cloned.shared_plan()));
    assert_eq!(binding.execution(), cloned.execution());
    assert_eq!(binding.runtime_generation(), OwnerGeneration::new(47));
    assert_eq!(binding.scope(), ResidentProxyBindingScope::Resident);
}

#[test]
fn binding_mark_policies_preserve_root_and_parent_rules() {
    let binding =
        ResidentProxyBinding::configuration(fixture_plan()).expect("configuration binding");
    assert_eq!(binding.effective_socket_mark(), 1234);
    assert_eq!(
        binding
            .clone()
            .with_route_socket_mark(4321)
            .effective_socket_mark(),
        4321
    );
    assert_eq!(
        binding
            .with_control_socket_mark(9876)
            .effective_socket_mark(),
        1234
    );
}

#[test]
fn control_plane_scope_is_explicit_and_materialized() {
    let binding =
        ResidentProxyBinding::control_plane(fixture_plan()).expect("control-plane binding");

    assert_eq!(binding.scope(), ResidentProxyBindingScope::ControlPlane);
    assert_eq!(binding.runtime_generation(), OwnerGeneration::new(0));
    assert_eq!(
        binding.execution().runtime_generation(),
        OwnerGeneration::new(0)
    );
}

#[test]
fn probe_reuse_policy_does_not_mutate_the_shared_plan() {
    let binding =
        ResidentProxyBinding::configuration(fixture_plan()).expect("configuration binding");
    let plan = Arc::clone(binding.shared_plan());
    let probe = binding.without_persistent_xhttp_reuse();

    assert_eq!(
        probe.xhttp_reuse_policy(),
        ResidentXhttpReusePolicy::NoPersistentReuse
    );
    assert!(!probe.xhttp_reuse_policy().allows_persistent_reuse());
    assert!(Arc::ptr_eq(&plan, probe.shared_plan()));
}

#[test]
fn binding_debug_is_credential_safe_and_size_is_bounded() {
    let binding =
        ResidentProxyBinding::configuration(fixture_plan()).expect("configuration binding");
    let debug = format!("{binding:?}");

    assert!(!debug.contains("binding-user"));
    assert!(!debug.contains("binding-secret"));
    assert!(std::mem::size_of::<ResidentProxyBinding>() <= 64);
}

#[test]
fn chain_binding_preserves_parent_protocols_generation_and_route_marks() {
    let mut plan = chain_fixture(
        "socks5://first-user:first-secret@127.0.0.1:28001 -> \
         http://second-user:second-secret@127.0.0.1:28002 -> \
         socks5://child-user:child-secret@127.0.0.1:28003",
    );
    set_chain_marks(&mut plan, &[101, 202, 303]);
    let plan = Arc::new(plan);
    let mut binding =
        ResidentProxyBinding::configuration(Arc::clone(&plan)).expect("chain binding");
    binding
        .bind_resident_generation(OwnerGeneration::new(47))
        .expect("bind chain generation");
    let route = binding.with_route_socket_mark(404);
    let first_parent = route
        .chain_parent()
        .expect("first parent binding")
        .expect("first parent");
    let second_parent = first_parent
        .chain_parent()
        .expect("second parent binding")
        .expect("second parent");

    assert_eq!(route.effective_socket_mark(), 404);
    assert_eq!(first_parent.effective_socket_mark(), 202);
    assert_eq!(second_parent.effective_socket_mark(), 303);
    assert_eq!(route.runtime_generation(), OwnerGeneration::new(47));
    assert_eq!(first_parent.runtime_generation(), OwnerGeneration::new(47));
    assert_eq!(second_parent.runtime_generation(), OwnerGeneration::new(47));
    assert!(matches!(
        &first_parent.plan().handler,
        ResidentProxyProtocolPlan::Socks5Tcp { .. }
    ));
    assert!(matches!(
        &second_parent.plan().handler,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. }
    ));
    assert!(Arc::ptr_eq(route.shared_plan(), &plan));
    assert_eq!(route.plan().graph_id, plan.graph_id);
    assert_eq!(route.plan().redacted_link_source, plan.redacted_link_source);
}

#[test]
fn chain_binding_applies_control_fallback_only_to_zero_mark_nodes() {
    let mut plan = chain_fixture(
        "socks5://first-user:first-secret@127.0.0.1:28101 -> \
         http://second-user:second-secret@127.0.0.1:28102 -> \
         socks5://child-user:child-secret@127.0.0.1:28103",
    );
    set_chain_marks(&mut plan, &[0, 0, 303]);
    let binding = ResidentProxyBinding::configuration(Arc::new(plan))
        .expect("control fallback chain binding")
        .with_control_socket_mark(909);
    let first_parent = binding
        .chain_parent()
        .expect("first control parent binding")
        .expect("first control parent");
    let second_parent = first_parent
        .chain_parent()
        .expect("second control parent binding")
        .expect("second control parent");

    assert_eq!(binding.effective_socket_mark(), 909);
    assert_eq!(first_parent.effective_socket_mark(), 909);
    assert_eq!(second_parent.effective_socket_mark(), 303);
}

#[test]
fn transport_identity_changes_when_a_parent_endpoint_changes() {
    let first = chain_fixture(
        "socks5://parent-user:parent-secret@127.0.0.1:28201 -> \
         socks5://child-user:child-secret@127.0.0.1:28202",
    );
    let mut changed = first.clone();
    Arc::make_mut(
        changed
            .chain_parent
            .as_mut()
            .expect("changed identity parent"),
    )
    .server_host = "127.0.0.2".to_owned();
    let first =
        ResidentProxyBinding::configuration(Arc::new(first)).expect("first identity binding");
    let changed =
        ResidentProxyBinding::configuration(Arc::new(changed)).expect("changed identity binding");

    assert_ne!(
        resident_transport_binding_identity_digest(BINDING_IDENTITY_TEST_DOMAIN, &first),
        resident_transport_binding_identity_digest(BINDING_IDENTITY_TEST_DOMAIN, &changed)
    );
    assert!(!format!("{first:?}").contains("parent-secret"));
    assert!(!format!("{changed:?}").contains("child-secret"));
}
