use crate::*;

pub(crate) struct Fixture {
    pub(crate) owner: runtime_owner::ResidentRuntimeOwner,
    pub(crate) config: Arc<Config>,
    pub(crate) fence: Arc<dns::ResidentDomainRoutingMapOwner>,
    pub(crate) coordinator: ResidentRuntimeCoordinator<ResidentDataplaneGeneration>,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let sections = dae_config::parser::parse_config(
            r#"
            global { lan_interface: daerust0 }
            node { local: 'socks5://127.0.0.1:1080#local' }
            group { proxy { filter: name(local) policy: fixed(0) } }
            routing { l4proto(tcp) -> proxy
 fallback: direct }
            "#,
        )
        .unwrap();
        let config = Arc::new(dae_config::schema::build_config(&sections).unwrap());
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let owner = runtime_owner::ResidentRuntimeOwner::new(
            std::env::temp_dir().join(format!(
                "resident-generation-{}-{}.jsonl",
                std::process::id(),
                next_resident_dataplane_generation_id().get()
            )),
            Arc::new(Mutex::new(())),
            1,
            Arc::new(ResidentDataplaneMetrics::default()),
            Arc::new(AtomicUsize::new(0)),
            resources,
            ResidentUdpPayloadAdmission::new(1, 1024 * 1024),
        )
        .unwrap();
        let gate = Arc::new(GenerationGate::default());
        let fence = Arc::new(dns::ResidentDomainRoutingMapOwner::with_gate(Arc::clone(
            &gate,
        )));
        let mut owner = owner;
        let first = Self::build(&mut owner, &config, &fence);
        let coordinator = ResidentRuntimeCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::clone(&first)),
            gate,
        );
        coordinator.publish(first.token(), first);
        Self {
            owner,
            config,
            fence,
            coordinator,
        }
    }

    fn build(
        owner: &mut runtime_owner::ResidentRuntimeOwner,
        config: &Arc<Config>,
        fence: &Arc<dns::ResidentDomainRoutingMapOwner>,
    ) -> Arc<ResidentDataplaneGeneration> {
        let prepared = plan::build_resident_prepared_dataplane_with_geodata(
            config,
            &ResidentGeodataStore::new(Vec::<PathBuf>::new()),
        )
        .unwrap();
        // Use the standard test routing handles here; kernel/map loading is
        // exercised separately by the native integration suite.
        let resources = owner.resource_config().clone();
        let groups = plan::share_resident_proxy_groups(prepared.plan.proxies.clone());
        let dns = Arc::new(prepared.plan.dns.clone());
        let (dns_resources, task) = dns.resource_owner(owner.stop_handle()).unwrap();
        owner.spawn_async_task("dns-resource-owner", "dns-resource-lifetime", async move {
            task.await;
        });
        let resolver = tcp::ResidentTcpDnsResolverPort::shared(
            ResidentDnsResolver::new(Arc::clone(&dns)).with_resource_lease(dns_resources.clone()),
        );
        let tcp_router = Arc::new(
            ResidentTcpRouter::new_for_test(
                plan::ResidentTcpProxyGroupSelector::shared(Arc::clone(&groups)),
                resolver,
                prepared.routing_matcher.clone(),
                prepared.plan.tcp_dial_mode,
                Duration::ZERO,
                0,
                false,
            )
            .unwrap(),
        );
        let udp_runtime =
            ResidentUdpRuntimeConfig::from_resources(1, &resources, owner.udp_payload_admission());
        let udp = udp::ResidentUdpGenerationPlan::for_generation_test(
            &prepared.plan,
            Arc::clone(&groups),
            prepared.routing_matcher,
            ResidentDnsDispatcher::new(Arc::clone(&dns)).with_resource_lease(dns_resources.clone()),
            udp_runtime,
        );
        let id = next_resident_dataplane_generation_id();
        let drain_control = ResidentGenerationDrainControl::new(id, ResidentStopSignal::shared());
        drain_control.activate().unwrap();
        let runtime_groups = groups.values().cloned().collect::<Vec<_>>();
        let probe_index = Arc::new(runtime_owner::ResidentManualProbeIndex::lazy(
            Arc::clone(config),
            1,
        ));
        let manual_probe_handle =
            owner.manual_probe_handle(&runtime_groups, &probe_index, &resources);
        let generation = Arc::new(ResidentDataplaneGeneration {
            id,
            reload_generation: PhysicalRuntimeId::new(1),
            tcp_router,
            tcp_admission: owner.tcp_admission(),
            tcp_flows: owner.tcp_flows(),
            tcp_runtime_config: ResidentTcpRuntimeConfig::new(
                2,
                resources.tcp_connection_limit.value(),
                resources.tcp_flow_stack_bytes.value(),
            ),
            dns_reload_handle: dns.reload_handle(),
            dns,
            dns_resources,
            udp,
            drain_control,
            metrics: owner.metrics(),
            groups: runtime_groups,
            manual_probe_handle,
            domain_routing_maintenance: None,
            _lifetime: ResidentDataplaneGenerationLifetime::register(),
        });
        let _ = fence;
        generation
    }

    pub(crate) fn next(&mut self) -> Arc<ResidentDataplaneGeneration> {
        Self::build(&mut self.owner, &self.config, &self.fence)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_socket_commits_to_current_generation_after_grant_and_reload() {
    let mut fixture = Fixture::new();
    let (epoch, first) = fixture.coordinator.load_versioned();
    let admission = fixture.owner.tcp_admission();
    admission.set_limit(1);
    let mut reservation = Some(admission.acquire().await.unwrap());
    let next = fixture.next();
    fixture.coordinator.publish(next.token(), Arc::clone(&next));
    assert!(
        tcp::try_commit_tcp_flow(&fixture.coordinator, epoch, &first, "tcp", &mut reservation)
            .is_none()
    );
    assert!(reservation.is_some());
    let (epoch, current) = fixture.coordinator.load_versioned();
    let lease = tcp::try_commit_tcp_flow(
        &fixture.coordinator,
        epoch,
        &current,
        "tcp",
        &mut reservation,
    )
    .unwrap()
    .unwrap();
    assert!(reservation.is_none());
    assert_eq!(
        fixture.owner.tcp_flows().snapshot()["byGeneration"][next.id.get().to_string()],
        1
    );
    current.request_stop();
    assert!(!lease.stop_handle().load(Ordering::Acquire));
    assert_eq!(admission.snapshot()["used"], 1);
    drop(lease);
    assert_eq!(admission.snapshot()["used"], 0);
    assert_eq!(fixture.owner.tcp_flows().snapshot()["releasedTotal"], 1);
    assert_eq!(fixture.owner.shutdown()["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_generation_pressure_and_age_do_not_stop_independent_tcp_leases() {
    for profile in [
        ResidentRuntimeProfile::LowMemory,
        ResidentRuntimeProfile::Balanced,
        ResidentRuntimeProfile::HighPerformance,
    ] {
        for udp in [false, true] {
            let mut fixture = Fixture::new();
            let policy = ResidentGenerationDrainPolicy::from_runtime_profile(profile);
            let drain = ResidentGenerationDrain::new(policy);
            let mut leases = Vec::new();
            let mut controls = Vec::new();
            let now = Instant::now();
            for _ in 0..policy.maximum_retired + 3 {
                let (epoch, current) = fixture.coordinator.load_versioned();
                let mut reservation = Some(fixture.owner.tcp_admission().acquire().await.unwrap());
                let lease = tcp::try_commit_tcp_flow(
                    &fixture.coordinator,
                    epoch,
                    &current,
                    "tcp",
                    &mut reservation,
                )
                .unwrap()
                .unwrap();
                if udp {
                    current.drain_control.register_udp_runtime();
                }
                controls.push(Arc::clone(&current.drain_control));
                leases.push(lease);
                let next = fixture.next();
                fixture.coordinator.publish(next.token(), next);
                drain.retire_shared_at(current, now);
                drain.commit_retirements();
                drain.prepare_publication_at(now).unwrap();
                assert!(
                    leases
                        .iter()
                        .all(|lease| !lease.stop_handle().load(Ordering::Acquire))
                );
            }
            drain
                .prepare_publication_at(now + policy.maximum_age + Duration::from_secs(1))
                .unwrap();
            assert!(
                controls
                    .iter()
                    .all(|control| control.udp_stop_is_requested())
            );
            assert!(
                leases
                    .iter()
                    .all(|lease| !lease.stop_handle().load(Ordering::Acquire))
            );
            fixture.owner.tcp_flows().stop_all();
            assert!(
                leases
                    .iter()
                    .all(|lease| lease.stop_handle().load(Ordering::Acquire))
            );
            drop(leases);
            assert_eq!(fixture.owner.tcp_admission().snapshot()["used"], 0);
            assert_eq!(fixture.owner.tcp_flows().snapshot()["active"], 0);
            assert_eq!(fixture.owner.shutdown()["status"], "pass");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_waiting_for_budget_commits_to_the_generation_current_when_granted() {
    let mut fixture = Fixture::new();
    let admission = fixture.owner.tcp_admission();
    admission.set_limit(1);
    let held = admission.acquire().await.unwrap();
    let old_id = fixture.coordinator.load().id;
    let mut waiting = Box::pin(admission.acquire());
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    let next = fixture.next();
    fixture.coordinator.publish(next.token(), next);
    drop(held);
    let mut granted = Some(waiting.await.unwrap());
    let (epoch, current) = fixture.coordinator.load_versioned();
    assert_ne!(current.id, old_id);
    let lease =
        tcp::try_commit_tcp_flow(&fixture.coordinator, epoch, &current, "tcp", &mut granted)
            .unwrap()
            .unwrap();
    assert_eq!(
        fixture.owner.tcp_flows().snapshot()["byGeneration"][current.id.get().to_string()],
        1
    );
    drop(lease);
    assert_eq!(admission.snapshot()["used"], 0);
    assert_eq!(admission.snapshot()["waiters"], 0);
    assert_eq!(fixture.owner.shutdown()["status"], "pass");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_failed_candidates_preserve_active_tcp_and_do_not_leak_owners() {
    let mut fixture = Fixture::new();
    let (epoch, active) = fixture.coordinator.load_versioned();
    let admission = fixture.owner.tcp_admission();
    admission.set_limit(1);
    let mut permit = Some(admission.acquire().await.unwrap());
    let lease = tcp::try_commit_tcp_flow(&fixture.coordinator, epoch, &active, "tcp", &mut permit)
        .unwrap()
        .unwrap();
    for _ in 0..16 {
        let mut prepared = plan::build_resident_prepared_dataplane_with_geodata(
            &fixture.config,
            &ResidentGeodataStore::new(Vec::<PathBuf>::new()),
        )
        .unwrap();
        prepared.plan.enabled = false;
        assert!(
            build_resident_dataplane_generation(ResidentGenerationBuildContext {
                owner: &mut fixture.owner,
                config: Arc::clone(&fixture.config),
                prepared,
                routing_tuple_map_id: None,
                domain_routing_map_id: None,
                domain_routing_fence: Arc::clone(&fixture.fence),
                latency_seed: &[],
                dns_reload_snapshot: None,
            })
            .is_err()
        );
        let candidate = fixture.next();
        candidate.request_stop();
        drop(candidate);
        assert_eq!(fixture.coordinator.load_versioned().0, epoch);
        assert!(!lease.stop_handle().load(Ordering::Acquire));
        assert_eq!(admission.snapshot()["used"], 1);
        assert_eq!(fixture.owner.tcp_flows().snapshot()["active"], 1);
    }
    drop(lease);
    assert_eq!(fixture.owner.tcp_flows().snapshot()["registeredTotal"], 1);
    assert_eq!(fixture.owner.tcp_flows().snapshot()["releasedTotal"], 1);
    assert_eq!(admission.snapshot()["used"], 0);
    assert_eq!(fixture.owner.shutdown()["status"], "pass");
}
