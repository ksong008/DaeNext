#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaedProductOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaedProductOutput {
    pub fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

pub fn help_text() -> String {
    r#"daed Rust native product commands:
  daed --version
  daed run -c /etc/daed --listen 0.0.0.0:2023 [--api-only] [--web-root PATH] [--control PATH]
  daed reload [--control PATH] [--timeout 60s] [--json]
  daed wait-ready [--control PATH] [--timeout 60s] [--json]
  daed validate -c /etc/daed/|/etc/dae/config.dae [--state /etc/daed/daed.db] [--runtime] [--json]
  daed service-contract [--json]
  daed package-info [--json]
  daed resident-adapter-matrix -c /etc/dae/config.dae [--json]
  daed resident-adapter-udp-live -c /etc/dae/config.dae --target HOST:PORT [--payload TEXT|--payload-hex HEX] [--json]
  daed state check --state /etc/daed/daed.db
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db [--force]
  daed export openapi|flatdesc|outline|package-manifest|admission-report|webui-route-audit|systemd-unit|docker-entrypoint
  daed resetpass -c /etc/daed [--json]
"#
    .to_owned()
}

use std::path::Path;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

mod shutdown;
pub use shutdown::*;

use dae_config::Config;
use serde_json::{Value, json};

mod process_metrics;
pub use process_metrics::*;
mod package;
pub use package::*;

const INTERNAL_RUNTIME_NODE_TAG_PREFIX: &str = "__daed_node_";
pub const DEFAULT_PRODUCT_CONTROL_SOCKET: &str = "/run/daed/control.sock";
pub const DEFAULT_PRODUCT_CONFIG_NAME: &str = "global";
pub const DEFAULT_PRODUCT_DNS_NAME: &str = "default";
pub const DEFAULT_PRODUCT_ROUTING_NAME: &str = "default";
pub const DEFAULT_PRODUCT_GROUP_NAME: &str = "default";
pub const GROUP_POLICY_RANDOM: &str = "random";
pub const GROUP_POLICY_FIXED: &str = "fixed";
pub const GROUP_POLICY_MIN: &str = "min";
pub const GROUP_POLICY_MIN_AVG10: &str = "min_avg10";
pub const GROUP_POLICY_MIN_MOVING_AVG: &str = "min_moving_avg";
pub const DEFAULT_PRODUCT_GROUP_POLICY: &str = GROUP_POLICY_RANDOM;
pub const DEFAULT_PRODUCT_MODE: &str = "rule";
pub const DEFAULT_GLOBAL_RESOURCE_TEXT: &str = "global {}";
pub const SUPPORTED_GROUP_POLICIES: &[&str] = &[
    GROUP_POLICY_RANDOM,
    GROUP_POLICY_FIXED,
    GROUP_POLICY_MIN,
    GROUP_POLICY_MIN_AVG10,
    GROUP_POLICY_MIN_MOVING_AVG,
];
pub const PRODUCT_CONTROL_SOCKET_ENV: &str = "DAED_CONTROL_SOCKET";
pub const RUNTIME_PROBE_GENERATION_METADATA_KEY: &str = "runtime_probe_generation";
pub const PRODUCT_LISTEN_ENV: &str = "PRODUCT_LISTEN";
pub const PRODUCT_LISTEN_LEGACY_ENV: &str = "DAED_LISTEN";

pub fn systemd_unit_text() -> String {
    r#"[Unit]
Description=daed is a integration solution of dae, API and UI.
Documentation=https://github.com/ksong008/DaeNext
After=network-online.target docker.service systemd-sysctl.service
Wants=network-online.target
Conflicts=dae.service

[Service]
Type=simple
User=root
LimitNPROC=512
LimitNOFILE=1048576
RuntimeDirectory=daed
RuntimeDirectoryMode=0700
ExecStartPre=/usr/bin/daed validate -c /etc/daed/
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/usr/bin/daed reload --timeout 60s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"#
    .to_owned()
}

pub fn docker_entrypoint_text() -> String {
    format!(
        r#"#!/bin/sh
set -eu
# Runtime defaults are owned by the binary; user-provided environment remains optional.
/usr/bin/daed validate -c /etc/daed/ >/dev/null
exec /usr/bin/daed run -c /etc/daed --listen "${{{PRODUCT_LISTEN_ENV}:-${{{PRODUCT_LISTEN_LEGACY_ENV}:-0.0.0.0:2023}}}}" "$@"
"#
    )
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeNodeTag(String);

impl RuntimeNodeTag {
    pub fn from_node_id(node_id: i64) -> Self {
        Self(format!("{INTERNAL_RUNTIME_NODE_TAG_PREFIX}{node_id}"))
    }

    pub fn from_existing(value: &str) -> Self {
        Self(value.trim().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

pub fn decode_product_label(value: &str) -> String {
    let value = value.trim();
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (
                product_hex_value(bytes[index + 1]),
                product_hex_value(bytes[index + 2]),
            )
        {
            output.push((high << 4) | low);
            changed = true;
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    if changed {
        String::from_utf8_lossy(&output).into_owned()
    } else {
        value.to_owned()
    }
}

fn product_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn runtime_node_tag(node: &Value) -> RuntimeNodeTag {
    if let Some(runtime_tag) = node
        .get("runtimeTag")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return RuntimeNodeTag::from_existing(runtime_tag);
    }
    if let Some(id) = node.get("id").and_then(Value::as_i64) {
        return RuntimeNodeTag::from_node_id(id);
    }
    let legacy_tag = node
        .get("tag")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            node.get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or("node_0");
    RuntimeNodeTag::from_existing(legacy_tag)
}

pub fn push_unique_runtime_node_tag(values: &mut Vec<RuntimeNodeTag>, value: RuntimeNodeTag) {
    if !values.iter().any(|seen| seen == &value) {
        values.push(value);
    }
}

pub fn product_render_routing_section(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return "routing {}\n".to_owned();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "routing {}\n".to_owned();
    }
    if dae_config::parser::parse_config(trimmed)
        .map(|sections| sections.iter().any(|section| section.name == "routing"))
        .unwrap_or(false)
    {
        return raw.to_owned();
    }
    format!("routing {{\n{trimmed}\n}}\n")
}

pub fn product_referenced_group_names_from_routing(
    routing_text: &str,
) -> Option<std::collections::BTreeSet<String>> {
    product_preferred_group_names_from_routing(routing_text)
        .map(|names| names.into_iter().collect())
}

pub fn product_preferred_group_names_from_routing(routing_text: &str) -> Option<Vec<String>> {
    use dae_config::Item;

    let sections = dae_config::parser::parse_config(routing_text).ok()?;
    let mut groups = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for section in &sections {
        if section.name != "routing" {
            continue;
        }
        for item in &section.items {
            if let Item::Param(param) = item
                && param.key == "fallback"
                && let Some(name) = product_routing_group_name(&param.val)
                && seen.insert(name.to_owned())
            {
                groups.push(name.to_owned());
            }
        }
    }
    for section in &sections {
        if section.name != "routing" {
            continue;
        }
        for item in &section.items {
            if let Item::RoutingRule(rule) = item
                && let Some(name) = product_routing_group_name(&rule.outbound.name)
                && seen.insert(name.to_owned())
            {
                groups.push(name.to_owned());
            }
        }
    }
    Some(groups)
}

fn product_routing_group_name(name: &str) -> Option<&str> {
    match name {
        "direct" | "must_direct" | "block" | "must_rules" => None,
        name => name
            .strip_prefix("must_")
            .filter(|stripped| !stripped.is_empty())
            .or(Some(name)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    Config,
    Dns,
    Routing,
}

impl SectionKind {
    pub fn from_path(path: &str) -> Option<Self> {
        if path == "/configs" || path.starts_with("/configs/") {
            Some(Self::Config)
        } else if path == "/dns" || path.starts_with("/dns/") {
            Some(Self::Dns)
        } else if path == "/routings" || path.starts_with("/routings/") {
            Some(Self::Routing)
        } else {
            None
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Self::Config => "/configs",
            Self::Dns => "/dns",
            Self::Routing => "/routings",
        }
    }

    pub fn table(self) -> &'static str {
        match self {
            Self::Config => "configs",
            Self::Dns => "dns",
            Self::Routing => "routings",
        }
    }

    pub fn value_column(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    pub fn request_value_key(self) -> &'static str {
        self.value_column()
    }

    pub fn default_name(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }
}

pub fn product_now_text() -> String {
    product_iso8601_utc(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

pub fn product_iso8601_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = product_civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub fn product_civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub const PRODUCT_HTTP_WORKERS_ENV: &str = "HTTP_WORKERS";
pub const PRODUCT_HTTP_WORKERS_LEGACY_ENV: &str = "DAED_HTTP_WORKERS";
pub const PRODUCT_HTTP_QUEUE_ENV: &str = "HTTP_QUEUE";
pub const PRODUCT_HTTP_QUEUE_LEGACY_ENV: &str = "DAED_HTTP_QUEUE";
pub const PRODUCT_HTTP_WORKER_STACK_BYTES_ENV: &str = "HTTP_WORKER_STACK_BYTES";
pub const PRODUCT_HTTP_WORKER_STACK_BYTES_LEGACY_ENV: &str = "DAED_HTTP_WORKER_STACK_BYTES";
pub const PRODUCT_HTTP_PROFILE_ENV: &str = "HTTP_PROFILE";
pub const PRODUCT_HTTP_PROFILE_LEGACY_ENV: &str = "DAED_HTTP_PROFILE";
pub const PRODUCT_HTTP_PROFILE_STANDARD: &str = "standard";
pub const PRODUCT_HTTP_PROFILE_LOW_MEMORY: &str = "low-memory";
pub const PRODUCT_HTTP_WORKER_DEFAULT_MIN: usize = 4;
pub const PRODUCT_HTTP_WORKER_DEFAULT_MAX: usize = 16;
pub const PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN: usize = 2;
pub const PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX: usize = 4;
pub const PRODUCT_HTTP_WORKER_MIN: usize = 1;
pub const PRODUCT_HTTP_WORKER_MAX: usize = 128;
pub const PRODUCT_HTTP_QUEUE_DEFAULT: usize = 256;
pub const PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT: usize = 128;
pub const PRODUCT_HTTP_QUEUE_MIN: usize = 16;
pub const PRODUCT_HTTP_QUEUE_MAX: usize = 16_384;
pub const PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT: usize = 1024 * 1024;
pub const PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT: usize = 512 * 1024;
pub const PRODUCT_HTTP_WORKER_STACK_BYTES_MIN: usize = 256 * 1024;
pub const PRODUCT_HTTP_WORKER_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductHttpProfile {
    Standard,
    LowMemory,
}

impl ProductHttpProfile {
    pub fn from_env() -> (Self, &'static str) {
        if let Some(profile) = std::env::var(PRODUCT_HTTP_PROFILE_ENV)
            .ok()
            .and_then(|value| Self::parse(&value))
        {
            return (profile, "env");
        }
        if let Some(profile) = std::env::var(PRODUCT_HTTP_PROFILE_LEGACY_ENV)
            .ok()
            .and_then(|value| Self::parse(&value))
        {
            return (profile, "compatibility-env");
        }
        (Self::Standard, "default")
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | PRODUCT_HTTP_PROFILE_STANDARD => Some(Self::Standard),
            "low" | "low_memory" | PRODUCT_HTTP_PROFILE_LOW_MEMORY => Some(Self::LowMemory),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => PRODUCT_HTTP_PROFILE_STANDARD,
            Self::LowMemory => PRODUCT_HTTP_PROFILE_LOW_MEMORY,
        }
    }

    pub fn worker_default_bounds(self) -> (usize, usize) {
        match self {
            Self::Standard => (
                PRODUCT_HTTP_WORKER_DEFAULT_MIN,
                PRODUCT_HTTP_WORKER_DEFAULT_MAX,
            ),
            Self::LowMemory => (
                PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN,
                PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX,
            ),
        }
    }

    pub fn queue_default(self) -> usize {
        match self {
            Self::Standard => PRODUCT_HTTP_QUEUE_DEFAULT,
            Self::LowMemory => PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT,
        }
    }

    pub fn worker_stack_bytes_default(self) -> usize {
        match self {
            Self::Standard => PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
            Self::LowMemory => PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductHttpWorkerConfig {
    pub profile: ProductHttpProfile,
    pub worker_count: usize,
    pub queue_capacity: usize,
    pub worker_stack_bytes: usize,
    pub profile_source: &'static str,
    pub worker_count_source: &'static str,
    pub queue_capacity_source: &'static str,
    pub worker_stack_bytes_source: &'static str,
}

impl ProductHttpWorkerConfig {
    pub fn from_config(config: Option<&Config>) -> Self {
        let (profile, profile_source) = ProductHttpProfile::from_env();
        Self::from_config_with_profile_and_env(config, profile, profile_source, &|name| {
            std::env::var(name).ok()
        })
    }

    pub fn from_config_with_profile(
        config: Option<&Config>,
        profile: ProductHttpProfile,
        profile_source: &'static str,
    ) -> Self {
        Self::from_config_with_profile_and_env(config, profile, profile_source, &|_| None)
    }

    pub fn from_config_with_profile_and_env(
        config: Option<&Config>,
        profile: ProductHttpProfile,
        profile_source: &'static str,
        env_value: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let global = config.map(|config| &config.global);
        let (default_worker_min, default_worker_max) = profile.worker_default_bounds();
        let default_workers = thread::available_parallelism()
            .map(|parallelism| parallelism.get().saturating_mul(2))
            .unwrap_or(default_worker_min)
            .clamp(default_worker_min, default_worker_max);
        let (worker_count, worker_count_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_WORKERS_ENV,
            PRODUCT_HTTP_WORKERS_LEGACY_ENV,
            global.and_then(|global| global.http_workers),
            default_workers,
            PRODUCT_HTTP_WORKER_MIN,
            PRODUCT_HTTP_WORKER_MAX,
        );
        let (queue_capacity, queue_capacity_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_QUEUE_ENV,
            PRODUCT_HTTP_QUEUE_LEGACY_ENV,
            global.and_then(|global| global.http_queue),
            profile.queue_default(),
            PRODUCT_HTTP_QUEUE_MIN,
            PRODUCT_HTTP_QUEUE_MAX,
        );
        let (worker_stack_bytes, worker_stack_bytes_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
            PRODUCT_HTTP_WORKER_STACK_BYTES_LEGACY_ENV,
            global.and_then(|global| global.http_worker_stack_bytes),
            profile.worker_stack_bytes_default(),
            PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
            PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
        );
        Self {
            profile,
            worker_count,
            queue_capacity,
            worker_stack_bytes,
            profile_source,
            worker_count_source,
            queue_capacity_source,
            worker_stack_bytes_source,
        }
    }

    pub fn sources_json(self) -> Value {
        json!({
            "profile": self.profile_source,
            "profileName": self.profile.name(),
            "workers": self.worker_count_source,
            "queue": self.queue_capacity_source,
            "workerStackBytes": self.worker_stack_bytes_source,
        })
    }

    pub fn transition_json(self, desired: Self) -> Value {
        json!({
            "state": "pending-process-transition",
            "owner": "product-http-runtime",
            "active": {
                "profile": self.profile.name(),
                "workers": self.worker_count,
                "queueCapacity": self.queue_capacity,
                "workerStackBytes": self.worker_stack_bytes,
                "sources": self.sources_json(),
            },
            "desired": {
                "profile": desired.profile.name(),
                "workers": desired.worker_count,
                "queueCapacity": desired.queue_capacity,
                "workerStackBytes": desired.worker_stack_bytes,
                "sources": desired.sources_json(),
            },
        })
    }
}

fn effective_product_usize_with_legacy(
    env_value: &dyn Fn(&str) -> Option<String>,
    name: &str,
    legacy_name: &str,
    configured: Option<u64>,
    default: usize,
    min: usize,
    max: usize,
) -> (usize, &'static str) {
    if let Some(value) = env_value(name).and_then(|value| value.trim().parse::<usize>().ok()) {
        return (value.clamp(min, max), "env");
    }
    if let Some(value) = env_value(legacy_name).and_then(|value| value.trim().parse::<usize>().ok())
    {
        return (value.clamp(min, max), "compatibility-env");
    }
    if let Some(value) = configured {
        return ((value as usize).clamp(min, max), "config");
    }
    (default.clamp(min, max), "default")
}
