use std::collections::HashMap;
use std::net::SocketAddr;

use crate::route::RouteRule;
use crate::tcp_route_dial::{
    RouteDialTcpPlan, RouteDialTcpPlanInput, TcpDialMode, route_dial_tcp_plan,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActiveL4 {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActiveHandoffKey {
    pub l4: ActiveL4,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveTcpHandoffInput {
    pub key: ActiveHandoffKey,
    pub dial_mode: TcpDialMode,
    pub initial_outbound: u8,
    pub sniffed_domain: Option<String>,
    pub domain_is_real: bool,
    pub initial_mark: u32,
    pub so_mark_from_dae: u32,
    pub mptcp: bool,
    pub route_rules: Vec<RouteRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveUdpHandoffInput {
    pub key: ActiveHandoffKey,
    pub outbound: u8,
    pub sniffed_domain: Option<String>,
    pub mark: u32,
    pub must: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveHandoffDecision {
    Tcp {
        key: ActiveHandoffKey,
        sniffed_domain: Option<String>,
        sniff_used: bool,
        plan: Box<RouteDialTcpPlan>,
        requires_outbound_adapter: bool,
    },
    Udp {
        key: ActiveHandoffKey,
        outbound: u8,
        sniffed_domain: Option<String>,
        sniff_used: bool,
        mark: u32,
        must: bool,
        requires_outbound_adapter: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveHandoffState {
    decisions: HashMap<ActiveHandoffKey, ActiveHandoffDecision>,
}

impl ActiveHandoffState {
    pub fn apply_tcp(&mut self, input: ActiveTcpHandoffInput) -> ActiveHandoffDecision {
        assert_eq!(input.key.l4, ActiveL4::Tcp);
        let domain = input.sniffed_domain.clone().unwrap_or_default();
        let plan = route_dial_tcp_plan(&RouteDialTcpPlanInput {
            dial_mode: input.dial_mode,
            initial_outbound: input.initial_outbound,
            destination: input.key.destination,
            domain,
            domain_is_real: input.domain_is_real,
            initial_mark: input.initial_mark,
            so_mark_from_dae: input.so_mark_from_dae,
            mptcp: input.mptcp,
            route_rules: input.route_rules,
        });
        let decision = ActiveHandoffDecision::Tcp {
            key: input.key,
            sniffed_domain: input.sniffed_domain.clone(),
            sniff_used: input.sniffed_domain.is_some(),
            plan: Box::new(plan),
            requires_outbound_adapter: true,
        };
        self.decisions.insert(input.key, decision.clone());
        decision
    }

    pub fn apply_udp(&mut self, input: ActiveUdpHandoffInput) -> ActiveHandoffDecision {
        assert_eq!(input.key.l4, ActiveL4::Udp);
        let decision = ActiveHandoffDecision::Udp {
            key: input.key,
            outbound: input.outbound,
            sniffed_domain: input.sniffed_domain.clone(),
            sniff_used: input.sniffed_domain.is_some(),
            mark: input.mark,
            must: input.must,
            requires_outbound_adapter: true,
        };
        self.decisions.insert(input.key, decision.clone());
        decision
    }

    pub fn remove(&mut self, key: &ActiveHandoffKey) -> Option<ActiveHandoffDecision> {
        self.decisions.remove(key)
    }

    pub fn get(&self, key: &ActiveHandoffKey) -> Option<&ActiveHandoffDecision> {
        self.decisions.get(key)
    }

    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_route_dial::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT};

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn tcp_handoff_uses_sniffed_domain_only_through_dial_mode_and_keeps_outbound_adapter_boundary()
    {
        let mut state = ActiveHandoffState::default();
        let key = ActiveHandoffKey {
            l4: ActiveL4::Tcp,
            source: addr("192.0.2.10:50123"),
            destination: addr("198.51.100.20:443"),
        };
        let decision = state.apply_tcp(ActiveTcpHandoffInput {
            key,
            dial_mode: TcpDialMode::DomainPlusPlus,
            initial_outbound: 2,
            sniffed_domain: Some("example.com".to_owned()),
            domain_is_real: true,
            initial_mark: 0,
            so_mark_from_dae: 1234,
            mptcp: true,
            route_rules: vec![RouteRule {
                kind: "Fallback".to_owned(),
                outbound: OUTBOUND_DIRECT,
                mark: 4321,
                must: false,
                matched: true,
            }],
        });
        let ActiveHandoffDecision::Tcp {
            sniff_used,
            plan,
            requires_outbound_adapter,
            ..
        } = decision
        else {
            panic!("expected TCP handoff decision")
        };
        assert!(sniff_used);
        assert!(requires_outbound_adapter);
        assert_eq!(plan.first_choose.dial_target, "example.com:443");
        assert!(plan.first_choose.should_reroute);
        assert_eq!(plan.final_outbound, OUTBOUND_DIRECT);
        assert_eq!(plan.final_mark, 4321);
        assert!(plan.userspace_route_executed);
    }

    #[test]
    fn udp_handoff_records_sniffed_domain_without_protocol_specific_outbound_logic() {
        let mut state = ActiveHandoffState::default();
        let key = ActiveHandoffKey {
            l4: ActiveL4::Udp,
            source: addr("192.0.2.10:50123"),
            destination: addr("198.51.100.53:443"),
        };
        let decision = state.apply_udp(ActiveUdpHandoffInput {
            key,
            outbound: OUTBOUND_CONTROL_PLANE_ROUTING,
            sniffed_domain: Some("video.example".to_owned()),
            mark: 0,
            must: false,
        });
        assert_eq!(state.len(), 1);
        let ActiveHandoffDecision::Udp {
            outbound,
            sniff_used,
            requires_outbound_adapter,
            ..
        } = decision
        else {
            panic!("expected UDP handoff decision")
        };
        assert_eq!(outbound, OUTBOUND_CONTROL_PLANE_ROUTING);
        assert!(sniff_used);
        assert!(requires_outbound_adapter);
        assert!(state.remove(&key).is_some());
        assert!(state.is_empty());
    }

    #[test]
    fn tcp_handoff_keeps_ip_mode_when_sniffed_domain_is_absent() {
        let mut state = ActiveHandoffState::default();
        let key = ActiveHandoffKey {
            l4: ActiveL4::Tcp,
            source: addr("192.0.2.10:50123"),
            destination: addr("198.51.100.20:443"),
        };
        let decision = state.apply_tcp(ActiveTcpHandoffInput {
            key,
            dial_mode: TcpDialMode::Domain,
            initial_outbound: OUTBOUND_BLOCK,
            sniffed_domain: None,
            domain_is_real: false,
            initial_mark: 0,
            so_mark_from_dae: 1234,
            mptcp: false,
            route_rules: Vec::new(),
        });
        let ActiveHandoffDecision::Tcp {
            sniff_used, plan, ..
        } = decision
        else {
            panic!("expected TCP handoff decision")
        };
        assert!(!sniff_used);
        assert_eq!(plan.final_dial_target, "198.51.100.20:443");
        assert_eq!(plan.final_mark, 1234);
        assert!(!plan.userspace_route_executed);
    }
}
