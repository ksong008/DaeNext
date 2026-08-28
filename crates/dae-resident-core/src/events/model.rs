use serde_json::{Value, json};

use super::{ResidentEventLogDecision, current_unix, event_log_decision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentEventKind {
    DnsBindQueryFinished,
    DnsPathChosen,
    TcpRouteChosen,
    UdpDnsPacketFinished,
    UdpPacketFinished,
    UdpPacketDropped,
    UdpReplyFailed,
    UdpRouteChosen,
    UdpSessionStarted,
    UdpSessionStopped,
}

impl ResidentEventKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::DnsBindQueryFinished => "dns_bind_query_finished",
            Self::DnsPathChosen => "dns_path_chosen",
            Self::TcpRouteChosen => "tcp_route_chosen",
            Self::UdpDnsPacketFinished => "udp_dns_packet_finished",
            Self::UdpPacketFinished => "udp_packet_finished",
            Self::UdpPacketDropped => "udp_packet_dropped",
            Self::UdpReplyFailed => "udp_reply_failed",
            Self::UdpRouteChosen => "udp_route_chosen",
            Self::UdpSessionStarted => "udp_session_started",
            Self::UdpSessionStopped => "udp_session_stopped",
        }
    }

    const fn lifecycle_class(self) -> ResidentEventLifecycleClass {
        match self {
            Self::TcpRouteChosen => ResidentEventLifecycleClass::Flow,
            Self::UdpDnsPacketFinished | Self::UdpPacketFinished => {
                ResidentEventLifecycleClass::Packet
            }
            Self::UdpPacketDropped => ResidentEventLifecycleClass::Packet,
            Self::UdpReplyFailed => ResidentEventLifecycleClass::Error,
            Self::UdpSessionStarted => ResidentEventLifecycleClass::Startup,
            Self::DnsBindQueryFinished
            | Self::DnsPathChosen
            | Self::UdpRouteChosen
            | Self::UdpSessionStopped => ResidentEventLifecycleClass::Debug,
        }
    }

    const fn severity(self) -> ResidentEventSeverity {
        match self {
            Self::UdpReplyFailed => ResidentEventSeverity::Error,
            _ => ResidentEventSeverity::Debug,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentEventMetadata {
    kind: ResidentEventKind,
    route_log_context: bool,
}

impl ResidentEventMetadata {
    pub const fn new(kind: ResidentEventKind) -> Self {
        Self {
            kind,
            route_log_context: false,
        }
    }

    pub const fn with_route_log_context(mut self) -> Self {
        self.route_log_context = true;
        self
    }

    pub const fn name(self) -> &'static str {
        self.kind.name()
    }

    pub const fn has_route_log_context(self) -> bool {
        self.route_log_context
    }

    const fn class(self) -> ResidentEventLifecycleClass {
        self.kind.lifecycle_class()
    }

    const fn severity(self) -> ResidentEventSeverity {
        self.kind.severity()
    }

    pub(super) const fn lossless(self) -> bool {
        self.class().is_lossless(self.severity())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResidentEventLifecycleClass {
    Startup,
    Reload,
    Error,
    Packet,
    Flow,
    Health,
    Debug,
}

impl ResidentEventLifecycleClass {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload => "reload",
            Self::Error => "error",
            Self::Packet => "packet",
            Self::Flow => "flow",
            Self::Health => "health",
            Self::Debug => "debug",
        }
    }

    fn from_event_name(event_name: &str) -> Self {
        if contains_ascii_ignore_case(event_name, "fatal")
            || contains_ascii_ignore_case(event_name, "failed")
            || contains_ascii_ignore_case(event_name, "error")
            || contains_ascii_ignore_case(event_name, "panic")
        {
            Self::Error
        } else if contains_ascii_ignore_case(event_name, "reload") {
            Self::Reload
        } else if contains_ascii_ignore_case(event_name, "startup")
            || contains_ascii_ignore_case(event_name, "started")
        {
            Self::Startup
        } else if contains_ascii_ignore_case(event_name, "health")
            || contains_ascii_ignore_case(event_name, "check")
        {
            Self::Health
        } else if contains_ascii_ignore_case(event_name, "packet")
            || contains_ascii_ignore_case(event_name, "udp_exchange")
            || contains_ascii_ignore_case(event_name, "dns_udp")
        {
            Self::Packet
        } else if contains_ascii_ignore_case(event_name, "tcp")
            || contains_ascii_ignore_case(event_name, "connection")
            || contains_ascii_ignore_case(event_name, "relay")
            || contains_ascii_ignore_case(event_name, "flow")
        {
            Self::Flow
        } else {
            Self::Debug
        }
    }

    pub(super) const fn is_lossless(self, severity: ResidentEventSeverity) -> bool {
        matches!(self, Self::Startup | Self::Reload | Self::Error)
            || matches!(
                severity,
                ResidentEventSeverity::Error | ResidentEventSeverity::Fatal
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResidentEventSeverity {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

impl ResidentEventSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Trace => 5,
            Self::Debug => 10,
            Self::Info => 50,
            Self::Warning => 70,
            Self::Error => 90,
            Self::Fatal => 100,
        }
    }

    fn from_event_name(event_name: &str, class: ResidentEventLifecycleClass) -> Self {
        if contains_ascii_ignore_case(event_name, "fatal") {
            Self::Fatal
        } else if matches!(class, ResidentEventLifecycleClass::Error) {
            Self::Error
        } else if contains_ascii_ignore_case(event_name, "dropped")
            || contains_ascii_ignore_case(event_name, "skipped")
            || contains_ascii_ignore_case(event_name, "timeout")
            || contains_ascii_ignore_case(event_name, "timed_out")
        {
            Self::Warning
        } else if matches!(
            class,
            ResidentEventLifecycleClass::Startup
                | ResidentEventLifecycleClass::Reload
                | ResidentEventLifecycleClass::Health
        ) {
            Self::Info
        } else if contains_ascii_ignore_case(event_name, "trace") {
            Self::Trace
        } else {
            Self::Debug
        }
    }
}

fn contains_ascii_ignore_case(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resident_event_classifier_matches_ascii_case_insensitive_names() {
        let fatal = ResidentEvent::new(json!({"event": "RESIDENT_FATAL_ERROR"}));
        assert_eq!(fatal.class(), ResidentEventLifecycleClass::Error);
        assert_eq!(fatal.severity, ResidentEventSeverity::Fatal);

        let packet = ResidentEvent::new(json!({"event": "UDP_EXCHANGE_FINISHED"}));
        assert_eq!(packet.class(), ResidentEventLifecycleClass::Packet);
        assert_eq!(packet.severity, ResidentEventSeverity::Debug);

        let warning = ResidentEvent::new(json!({"event": "tcp_probe_timeout"}));
        assert_eq!(warning.class(), ResidentEventLifecycleClass::Flow);
        assert_eq!(warning.severity, ResidentEventSeverity::Warning);

        let startup = ResidentEvent::new(json!({"event": "TCP_WORKER_STARTED"}));
        assert_eq!(startup.class(), ResidentEventLifecycleClass::Startup);
        assert_eq!(startup.severity, ResidentEventSeverity::Info);
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentEvent {
    value: Value,
    decision: ResidentEventLogDecision,
    class: ResidentEventLifecycleClass,
    severity: ResidentEventSeverity,
    priority: u8,
}

impl ResidentEvent {
    pub(super) fn new(value: Value) -> Self {
        let event_name = value.get("event").and_then(Value::as_str).unwrap_or("");
        let class = ResidentEventLifecycleClass::from_event_name(event_name);
        let severity = ResidentEventSeverity::from_event_name(event_name, class);
        let decision = event_log_decision(&value);
        Self {
            value,
            decision,
            class,
            severity,
            priority: severity.priority(),
        }
    }

    pub(super) fn from_metadata(
        value: Value,
        metadata: ResidentEventMetadata,
        decision: ResidentEventLogDecision,
    ) -> Self {
        debug_assert_eq!(
            value.get("event").and_then(Value::as_str),
            Some(metadata.name())
        );
        let class = metadata.class();
        let severity = metadata.severity();
        Self {
            value,
            decision,
            class,
            severity,
            priority: severity.priority(),
        }
    }

    pub(super) fn class(&self) -> ResidentEventLifecycleClass {
        self.class
    }

    pub(super) fn lossless(&self) -> bool {
        self.class.is_lossless(self.severity)
    }

    /// Critical lifecycle events: Startup/Reload lifecycle classes and any
    /// Fatal-severity event.
    ///
    /// These used to block on a full writer queue. Event submission is now
    /// non-blocking (see `writer::submit_event`): when the bounded queue forces
    /// a drop, the loss of a critical event is surfaced in the writer error
    /// metrics instead of being silently counted.
    pub(super) fn is_critical(&self) -> bool {
        matches!(
            (self.class, self.severity),
            (ResidentEventLifecycleClass::Startup, _)
                | (ResidentEventLifecycleClass::Reload, _)
                | (_, ResidentEventSeverity::Fatal)
        )
    }

    pub(super) fn should_persist(&self) -> bool {
        self.decision.persist || self.lossless()
    }

    pub(super) fn into_serializable_value(mut self) -> Value {
        if let Value::Object(map) = &mut self.value {
            map.entry("eventSchemaVersion".to_owned())
                .or_insert_with(|| json!(1));
            map.entry("timestampUnix".to_owned())
                .or_insert_with(|| json!(current_unix()));
            map.entry("severity".to_owned())
                .or_insert_with(|| json!(self.severity.as_str()));
            map.entry("priority".to_owned())
                .or_insert_with(|| json!(self.priority));
            map.entry("lifecycleClass".to_owned())
                .or_insert_with(|| json!(self.class.as_str()));
            if let Some(level) = self.decision.level.as_deref() {
                map.entry("residentLogLevel".to_owned())
                    .or_insert_with(|| json!(level));
            }
        }
        self.value
    }
}

#[derive(Debug)]
pub(super) struct ResidentEventPersistOutcome {
    pub(super) persisted: bool,
    pub(super) pruned: bool,
}
