use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) struct RuntimeTransitionIdentity {
    pub(in crate::daed_product) routing_version: i64,
    pub(in crate::daed_product) geodata_input_version: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum RuntimeTransitionClass {
    NoChange,
    GenerationSwap,
    KernelRebind,
    ProcessRestart,
}

impl RuntimeTransitionClass {
    pub(in crate::daed_product) const fn name(self) -> &'static str {
        match self {
            Self::NoChange => "NoChange",
            Self::GenerationSwap => "GenerationSwap",
            Self::KernelRebind => "KernelRebind",
            Self::ProcessRestart => "ProcessRestart",
        }
    }
}

pub(in crate::daed_product) fn classify_runtime_transition(
    active: &Config,
    active_identity: Option<RuntimeTransitionIdentity>,
    desired: &Config,
    desired_identity: Option<RuntimeTransitionIdentity>,
) -> RuntimeTransitionClass {
    let identity_changed = active_identity != desired_identity;
    if active == desired && !identity_changed {
        return RuntimeTransitionClass::NoChange;
    }
    if identity_changed || kernel_ownership_changed(active, desired) {
        return RuntimeTransitionClass::KernelRebind;
    }
    if equivalent_without_generation_publication(active, desired) {
        if process_owned_fields_changed(active, desired) {
            return RuntimeTransitionClass::ProcessRestart;
        }
        return RuntimeTransitionClass::NoChange;
    }
    RuntimeTransitionClass::GenerationSwap
}

pub(in crate::daed_product) fn process_owned_field_changes(
    active: &Config,
    desired: &Config,
) -> Vec<&'static str> {
    let active = &active.global;
    let desired = &desired.global;
    let mut changed = Vec::new();
    macro_rules! record {
        ($field:ident) => {
            if active.$field != desired.$field {
                changed.push(stringify!($field));
            }
        };
    }
    record!(pprof_port);
    record!(resident_tcp_flow_stack_bytes);
    record!(resident_tcp_runtime_workers);
    record!(resident_event_queue_depth);
    record!(http_queue);
    record!(http_workers);
    record!(http_worker_stack_bytes);
    record!(allocator_idle_reclaim_enabled);
    record!(allocator_idle_reclaim_sample_interval);
    record!(allocator_idle_reclaim_min_interval);
    record!(allocator_idle_reclaim_low_traffic_duration);
    record!(allocator_idle_reclaim_pressure_threshold_bytes);
    record!(allocator_idle_reclaim_max_traffic_rate_bytes_per_second);
    changed
}

fn kernel_ownership_changed(active: &Config, desired: &Config) -> bool {
    active.routing != desired.routing
        || active.dns.bind != desired.dns.bind
        || active.global.tproxy_port != desired.global.tproxy_port
        || active.global.tproxy_port_protect != desired.global.tproxy_port_protect
        || active.global.lan_interface != desired.global.lan_interface
        || active.global.wan_interface != desired.global.wan_interface
        || active.global.disable_waiting_network != desired.global.disable_waiting_network
        || active.global.enable_local_tcp_fast_redirect
            != desired.global.enable_local_tcp_fast_redirect
        || active.global.auto_config_kernel_parameter != desired.global.auto_config_kernel_parameter
        || active.global.auto_config_firewall_rule != desired.global.auto_config_firewall_rule
}

fn process_owned_fields_changed(active: &Config, desired: &Config) -> bool {
    !process_owned_field_changes(active, desired).is_empty()
}

fn equivalent_without_generation_publication(active: &Config, desired: &Config) -> bool {
    let mut normalized = desired.clone();
    normalized
        .global
        .log_level
        .clone_from(&active.global.log_level);
    normalized.global.pprof_port = active.global.pprof_port;
    normalized.global.resident_tcp_flow_stack_bytes = active.global.resident_tcp_flow_stack_bytes;
    normalized.global.resident_tcp_runtime_workers = active.global.resident_tcp_runtime_workers;
    normalized.global.resident_event_queue_depth = active.global.resident_event_queue_depth;
    normalized.global.http_queue = active.global.http_queue;
    normalized.global.http_workers = active.global.http_workers;
    normalized.global.http_worker_stack_bytes = active.global.http_worker_stack_bytes;
    normalized.global.allocator_idle_reclaim_enabled = active.global.allocator_idle_reclaim_enabled;
    normalized.global.allocator_idle_reclaim_sample_interval =
        active.global.allocator_idle_reclaim_sample_interval;
    normalized.global.allocator_idle_reclaim_min_interval =
        active.global.allocator_idle_reclaim_min_interval;
    normalized
        .global
        .allocator_idle_reclaim_low_traffic_duration =
        active.global.allocator_idle_reclaim_low_traffic_duration;
    normalized
        .global
        .allocator_idle_reclaim_pressure_threshold_bytes = active
        .global
        .allocator_idle_reclaim_pressure_threshold_bytes;
    normalized
        .global
        .allocator_idle_reclaim_max_traffic_rate_bytes_per_second = active
        .global
        .allocator_idle_reclaim_max_traffic_rate_bytes_per_second;
    active == &normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            global: Default::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Default::default(),
            dns: Default::default(),
        }
    }

    #[test]
    fn logical_changes_use_generation_swap() {
        let active = test_config();
        let mut desired = active.clone();
        desired.global.allow_insecure = true;
        assert_eq!(
            classify_runtime_transition(&active, None, &desired, None),
            RuntimeTransitionClass::GenerationSwap
        );
    }

    #[test]
    fn routing_and_bind_changes_require_kernel_rebind() {
        let active = test_config();
        let mut desired = active.clone();
        desired.dns.bind = "127.0.0.1:5353".to_owned();
        assert_eq!(
            classify_runtime_transition(&active, None, &desired, None),
            RuntimeTransitionClass::KernelRebind
        );
    }

    #[test]
    fn process_only_changes_are_deferred() {
        let active = test_config();
        let mut desired = active.clone();
        desired.global.resident_tcp_runtime_workers = Some(3);
        assert_eq!(
            classify_runtime_transition(&active, None, &desired, None),
            RuntimeTransitionClass::ProcessRestart
        );
    }

    #[test]
    fn logical_and_process_changes_publish_generation_and_defer_process_policy() {
        let active = test_config();
        let mut desired = active.clone();
        desired.global.allow_insecure = true;
        desired.global.resident_tcp_runtime_workers = Some(3);
        assert_eq!(
            classify_runtime_transition(&active, None, &desired, None),
            RuntimeTransitionClass::GenerationSwap
        );
        assert_eq!(
            process_owned_field_changes(&active, &desired),
            vec!["resident_tcp_runtime_workers"]
        );
    }

    #[test]
    fn log_policy_change_does_not_publish_a_dataplane_generation() {
        let active = test_config();
        let mut desired = active.clone();
        desired.global.log_level = "debug".to_owned();
        assert_eq!(
            classify_runtime_transition(&active, None, &desired, None),
            RuntimeTransitionClass::NoChange
        );
    }

    #[test]
    fn geodata_revision_requires_kernel_rebind_until_atomic_maps_exist() {
        let config = test_config();
        let active = RuntimeTransitionIdentity {
            routing_version: 1,
            geodata_input_version: 2,
        };
        let desired = RuntimeTransitionIdentity {
            geodata_input_version: 3,
            ..active
        };
        assert_eq!(
            classify_runtime_transition(&config, Some(active), &config, Some(desired)),
            RuntimeTransitionClass::KernelRebind
        );
    }
}
