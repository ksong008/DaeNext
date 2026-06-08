use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachSectionPrefix {
    Tc,
    Classifier,
}

impl TcAttachSectionPrefix {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tc => "tc",
            Self::Classifier => "classifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachLayer {
    L2,
    L3,
}

impl TcAttachLayer {
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::L2 => "l2",
            Self::L3 => "l3",
        }
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

    pub(super) fn tc_command(&self, args: impl IntoIterator<Item = String>) -> TcCommandSpec {
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

    pub fn native_attach_spec(
        &self,
        program_name: impl Into<String>,
        priority: u16,
        handle: u32,
    ) -> TcNativeAttachSpec {
        TcNativeAttachSpec {
            target: self.target.clone(),
            object: self.object.clone(),
            section: self.section.clone(),
            program_name: program_name.into(),
            priority,
            handle,
            tcx_order: TcxAttachOrder::from_go_tc_priority(priority),
            protocol: ETH_P_ALL,
            direct_action: self.direct_action,
            clsact_required: true,
            netns_enter_required: self.target.netns.is_some(),
            link_lifetime_owned_by_backend: true,
        }
    }

    pub fn attach_backend_report(
        &self,
        requested: AttachBackend,
        kernel_version: Option<Version>,
        availability: AttachBackendAvailability,
        default_native_backend_enabled: bool,
        native_spec: TcNativeAttachSpec,
    ) -> TcAttachBackendReport {
        let plan = plan_attach_backend(requested, kernel_version, availability);
        let native_backend_capable = matches!(
            plan.selected,
            Some(AttachBackend::Tcx | AttachBackend::TcNetlink)
        );
        let effective_backend = if default_native_backend_enabled {
            plan.selected
        } else {
            Some(AttachBackend::TcCommandFallback)
        };
        TcAttachBackendReport {
            tcx_attempted: plan.attempt_order.contains(&AttachBackend::Tcx),
            tc_netlink_attempted: plan.attempt_order.contains(&AttachBackend::TcNetlink),
            command_fallback_attempted: plan
                .attempt_order
                .contains(&AttachBackend::TcCommandFallback),
            command_fallback_required: effective_backend == Some(AttachBackend::TcCommandFallback),
            command_fallback_spec: self.filter_add_command(),
            cleanup_fallback_spec: self.filter_del_command(),
            show_fallback_spec: self.filter_show_command(true),
            plan,
            native_spec,
            effective_backend,
            default_native_backend_enabled,
            native_backend_capable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}
