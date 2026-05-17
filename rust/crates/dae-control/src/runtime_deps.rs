#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentGate {
    pub name: &'static str,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDependencyPlan {
    pub gates: Vec<EnvironmentGate>,
}

impl RuntimeDependencyPlan {
    pub fn stage7_default() -> Self {
        Self {
            gates: vec![
                EnvironmentGate {
                    name: "root",
                    required: true,
                },
                EnvironmentGate {
                    name: "bpffs",
                    required: true,
                },
                EnvironmentGate {
                    name: "netns_permission",
                    required: true,
                },
                EnvironmentGate {
                    name: "memlock",
                    required: true,
                },
                EnvironmentGate {
                    name: "kernel_feature_version",
                    required: true,
                },
            ],
        }
    }
}
