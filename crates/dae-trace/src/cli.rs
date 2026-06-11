use crate::DEFAULT_RINGBUF_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceCommandSurface {
    pub feature_gated: bool,
    pub build_tag: &'static str,
    pub use_name: &'static str,
    pub short: &'static str,
    pub defaults: TraceDefaults,
    pub flags: Vec<TraceFlag>,
    pub output_fields: Vec<&'static str>,
    pub target_discovery: TraceTargetDiscovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceDefaults {
    pub ipv4_when_unspecified: bool,
    pub l4_proto: &'static str,
    pub port: u16,
    pub drop_only: bool,
    pub output: &'static str,
    pub ringbuf_size: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFlag {
    pub name: &'static str,
    pub shorthand: &'static str,
    pub default: TraceFlagDefault,
    pub values: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceFlagDefault {
    Bool(bool),
    Number(u16),
    Text(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceTargetDiscovery {
    pub uses_kernel_btf: bool,
    pub max_skb_arg_position: u8,
    pub requires_attached_target: bool,
}

pub fn default_trace_command_surface() -> TraceCommandSurface {
    TraceCommandSurface {
        feature_gated: true,
        build_tag: "trace",
        use_name: "trace",
        short: "To trace traffic",
        defaults: TraceDefaults {
            ipv4_when_unspecified: true,
            l4_proto: "tcp",
            port: 80,
            drop_only: false,
            output: "/dev/stdout",
            ringbuf_size: DEFAULT_RINGBUF_SIZE,
        },
        flags: vec![
            TraceFlag {
                name: "ipv4",
                shorthand: "4",
                default: TraceFlagDefault::Bool(false),
                values: vec![],
            },
            TraceFlag {
                name: "ipv6",
                shorthand: "6",
                default: TraceFlagDefault::Bool(false),
                values: vec![],
            },
            TraceFlag {
                name: "l4-proto",
                shorthand: "p",
                default: TraceFlagDefault::Text("tcp"),
                values: vec!["tcp", "udp"],
            },
            TraceFlag {
                name: "port",
                shorthand: "P",
                default: TraceFlagDefault::Number(80),
                values: vec![],
            },
            TraceFlag {
                name: "drop-only",
                shorthand: "",
                default: TraceFlagDefault::Bool(false),
                values: vec![],
            },
            TraceFlag {
                name: "output",
                shorthand: "o",
                default: TraceFlagDefault::Text("/dev/stdout"),
                values: vec![],
            },
            TraceFlag {
                name: "ringbuf-size",
                shorthand: "",
                default: TraceFlagDefault::Text(DEFAULT_RINGBUF_SIZE),
                values: vec![],
            },
        ],
        output_fields: vec![
            "skb",
            "mark",
            "netns",
            "ifindex",
            "ifname",
            "pid",
            "pname",
            "src",
            "dst",
            "tcp_flags",
            "payload_len",
            "symbol",
            "drop_reason",
        ],
        target_discovery: TraceTargetDiscovery {
            uses_kernel_btf: true,
            max_skb_arg_position: 5,
            requires_attached_target: true,
        },
    }
}
