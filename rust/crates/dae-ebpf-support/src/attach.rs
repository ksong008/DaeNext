use crate::kernel::Version;

pub const TCX_ATTACH_FEATURE_VERSION: Version = Version::new(6, 6, 0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachBackend {
    Auto,
    TcCommandFallback,
    TcNetlink,
    Tcx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachBackendAvailability {
    pub tcx: bool,
    pub tc_netlink: bool,
    pub tc_command_fallback: bool,
}

impl AttachBackendAvailability {
    pub const fn command_fallback_only() -> Self {
        Self {
            tcx: false,
            tc_netlink: false,
            tc_command_fallback: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachBackendPlan {
    pub requested: AttachBackend,
    pub kernel_version: Option<Version>,
    pub tcx_supported: bool,
    pub attempt_order: Vec<AttachBackend>,
    pub selected: Option<AttachBackend>,
    pub command_fallback_used: bool,
}

pub fn plan_attach_backend(
    requested: AttachBackend,
    kernel_version: Option<Version>,
    availability: AttachBackendAvailability,
) -> AttachBackendPlan {
    let tcx_supported = kernel_version
        .map(|version| version >= TCX_ATTACH_FEATURE_VERSION)
        .unwrap_or(false);
    let attempt_order = match requested {
        AttachBackend::Auto => {
            let mut order = Vec::new();
            if tcx_supported {
                order.push(AttachBackend::Tcx);
            }
            order.push(AttachBackend::TcNetlink);
            order.push(AttachBackend::TcCommandFallback);
            order
        }
        backend => vec![backend],
    };
    let selected = attempt_order.iter().copied().find(|backend| match backend {
        AttachBackend::Auto => false,
        AttachBackend::Tcx => tcx_supported && availability.tcx,
        AttachBackend::TcNetlink => availability.tc_netlink,
        AttachBackend::TcCommandFallback => availability.tc_command_fallback,
    });
    AttachBackendPlan {
        requested,
        kernel_version,
        tcx_supported,
        attempt_order,
        selected,
        command_fallback_used: selected == Some(AttachBackend::TcCommandFallback),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachDirection {
    Ingress,
    Egress,
}

impl TcAttachDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAttachTarget {
    pub iface: String,
    pub netns: Option<String>,
    pub direction: TcAttachDirection,
}

impl TcAttachTarget {
    pub fn host(iface: impl Into<String>, direction: TcAttachDirection) -> Self {
        Self {
            iface: iface.into(),
            netns: None,
            direction,
        }
    }

    pub fn netns(
        netns: impl Into<String>,
        iface: impl Into<String>,
        direction: TcAttachDirection,
    ) -> Self {
        Self {
            iface: iface.into(),
            netns: Some(netns.into()),
            direction,
        }
    }

    pub fn clsact_qdisc_add_command(&self) -> TcCommandSpec {
        self.tc_command([
            "qdisc".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            "clsact".to_owned(),
        ])
    }

    pub fn clsact_qdisc_del_command(&self) -> TcCommandSpec {
        self.tc_command([
            "qdisc".to_owned(),
            "del".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            "clsact".to_owned(),
        ])
    }

    pub fn filter_show_command(&self, stats: bool) -> TcCommandSpec {
        let mut args = Vec::new();
        if stats {
            args.push("-s".to_owned());
        }
        args.extend([
            "filter".to_owned(),
            "show".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            self.direction.as_str().to_owned(),
        ]);
        self.tc_command(args)
    }

    pub fn filter_del_command(&self, pref: impl Into<String>) -> TcCommandSpec {
        self.tc_command([
            "filter".to_owned(),
            "del".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            self.direction.as_str().to_owned(),
            "pref".to_owned(),
            pref.into(),
        ])
    }

    fn tc_command(&self, args: impl IntoIterator<Item = String>) -> TcCommandSpec {
        let args = args.into_iter().collect::<Vec<_>>();
        match &self.netns {
            Some(netns) => {
                let mut wrapped = vec![
                    "netns".to_owned(),
                    "exec".to_owned(),
                    netns.clone(),
                    "tc".to_owned(),
                ];
                wrapped.extend(args);
                TcCommandSpec {
                    program: "ip".to_owned(),
                    args: wrapped,
                }
            }
            None => TcCommandSpec {
                program: "tc".to_owned(),
                args,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcBpfAttachSpec {
    pub target: TcAttachTarget,
    pub pref: String,
    pub object: String,
    pub section: String,
    pub direct_action: bool,
}

impl TcBpfAttachSpec {
    pub fn new(
        target: TcAttachTarget,
        pref: impl Into<String>,
        object: impl Into<String>,
        section: impl Into<String>,
    ) -> Self {
        Self {
            target,
            pref: pref.into(),
            object: object.into(),
            section: section.into(),
            direct_action: true,
        }
    }

    pub fn filter_add_command(&self) -> TcCommandSpec {
        let mut args = vec![
            "filter".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.target.iface.clone(),
            self.target.direction.as_str().to_owned(),
            "pref".to_owned(),
            self.pref.clone(),
            "bpf".to_owned(),
        ];
        if self.direct_action {
            args.push("da".to_owned());
        }
        args.extend([
            "obj".to_owned(),
            self.object.clone(),
            "sec".to_owned(),
            self.section.clone(),
        ]);
        self.target.tc_command(args)
    }

    pub fn filter_show_command(&self, stats: bool) -> TcCommandSpec {
        self.target.filter_show_command(stats)
    }

    pub fn filter_del_command(&self) -> TcCommandSpec {
        self.target.filter_del_command(self.pref.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}
