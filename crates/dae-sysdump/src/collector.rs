#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorContract {
    pub name: &'static str,
    pub output: &'static str,
    pub failure: &'static str,
}

pub fn default_collectors() -> Vec<CollectorContract> {
    vec![
        collector("routing", "routing.txt"),
        collector("interfaces", "interfaces.txt"),
        collector("sysctl", "sysctl.txt"),
        collector("nftables", "nftables.txt"),
        collector("iptables", "iptables.txt"),
        collector("ip6tables", "ip6tables.txt"),
    ]
}

fn collector(name: &'static str, output: &'static str) -> CollectorContract {
    CollectorContract {
        name,
        output,
        failure: "print error and continue",
    }
}
