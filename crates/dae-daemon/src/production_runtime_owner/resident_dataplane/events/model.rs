use serde_json::{Value, json};

use super::{ResidentEventLogDecision, current_unix, event_log_decision};

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
        let lower = event_name.to_ascii_lowercase();
        if lower.contains("fatal")
            || lower.contains("failed")
            || lower.contains("error")
            || lower.contains("panic")
        {
            Self::Error
        } else if lower.contains("reload") {
            Self::Reload
        } else if lower.contains("startup") || lower.contains("started") {
            Self::Startup
        } else if lower.contains("health") || lower.contains("check") {
            Self::Health
        } else if lower.contains("packet")
            || lower.contains("udp_exchange")
            || lower.contains("dns_udp")
        {
            Self::Packet
        } else if lower.contains("tcp")
            || lower.contains("connection")
            || lower.contains("relay")
            || lower.contains("flow")
        {
            Self::Flow
        } else {
            Self::Debug
        }
    }

    pub(super) fn is_lossless(self, severity: ResidentEventSeverity) -> bool {
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
        let lower = event_name.to_ascii_lowercase();
        if lower.contains("fatal") {
            Self::Fatal
        } else if matches!(class, ResidentEventLifecycleClass::Error) {
            Self::Error
        } else if lower.contains("dropped")
            || lower.contains("skipped")
            || lower.contains("timeout")
            || lower.contains("timed_out")
        {
            Self::Warning
        } else if matches!(
            class,
            ResidentEventLifecycleClass::Startup
                | ResidentEventLifecycleClass::Reload
                | ResidentEventLifecycleClass::Health
        ) {
            Self::Info
        } else if lower.contains("trace") {
            Self::Trace
        } else {
            Self::Debug
        }
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

    pub(super) fn class(&self) -> ResidentEventLifecycleClass {
        self.class
    }

    pub(super) fn lossless(&self) -> bool {
        self.class.is_lossless(self.severity)
    }

    pub(super) fn should_persist(&self) -> bool {
        self.decision.persist || self.lossless()
    }

    pub(super) fn max_entries(&self) -> usize {
        self.decision.max_entries
    }

    pub(super) fn max_bytes(&self) -> u64 {
        self.decision.max_bytes
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
