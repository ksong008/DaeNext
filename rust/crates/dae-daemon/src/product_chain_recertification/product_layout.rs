use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(super) struct ProductPathLayout {
    pub(super) kind: &'static str,
    pub(super) binary_target: &'static str,
    pub(super) local_binary_target: &'static str,
    pub(super) service_name: &'static str,
    pub(super) service_target: &'static str,
    pub(super) service_paths: &'static [&'static str],
    pub(super) config_target: &'static str,
    pub(super) current_exec_start_pre: &'static str,
    pub(super) current_exec_start: &'static str,
    pub(super) current_exec_reload: &'static str,
    pub(super) target_run_binary: &'static str,
    pub(super) target_exec_start_pre: &'static str,
    pub(super) target_exec_start: &'static str,
    pub(super) target_exec_reload: &'static str,
    pub(super) backup_service_file_name: &'static str,
    pub(super) backup_binary_file_name: &'static str,
    pub(super) backup_local_binary_file_name: &'static str,
}

const DAE_SERVICE_PATHS: &[&str] = &[
    "/etc/systemd/system/dae.service",
    "/usr/lib/systemd/system/dae.service",
    "/lib/systemd/system/dae.service",
];

const DAED_SERVICE_PATHS: &[&str] = &[
    "/etc/systemd/system/daed.service",
    "/usr/lib/systemd/system/daed.service",
    "/lib/systemd/system/daed.service",
];

const DAE_LAYOUT: ProductPathLayout = ProductPathLayout {
    kind: "dae",
    binary_target: "/usr/bin/dae",
    local_binary_target: "/usr/local/bin/dae",
    service_name: "dae.service",
    service_target: "/etc/systemd/system/dae.service",
    service_paths: DAE_SERVICE_PATHS,
    config_target: "/etc/dae/config.dae",
    current_exec_start_pre: "/usr/bin/dae validate -c /etc/dae/config.dae",
    current_exec_start: "/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae",
    current_exec_reload: "/usr/bin/dae reload $MAINPID",
    target_run_binary: "dae-daemon-optin",
    target_exec_start_pre: "dae-daemon-optin validate -c /etc/dae/config.dae",
    target_exec_start: "dae-daemon-optin run --disable-timestamp -c /etc/dae/config.dae",
    target_exec_reload: "dae-daemon-optin reload $MAINPID",
    backup_service_file_name: "dae.service",
    backup_binary_file_name: "usr-bin-dae",
    backup_local_binary_file_name: "usr-local-bin-dae",
};

const DAED_LAYOUT: ProductPathLayout = ProductPathLayout {
    kind: "daed",
    binary_target: "/usr/bin/daed",
    local_binary_target: "/usr/local/bin/daed",
    service_name: "daed.service",
    service_target: "/etc/systemd/system/daed.service",
    service_paths: DAED_SERVICE_PATHS,
    config_target: "/etc/daed/",
    current_exec_start_pre: "/usr/bin/daed validate -c /etc/daed/",
    current_exec_start: "/usr/bin/daed run -c /etc/daed/",
    current_exec_reload: "/bin/kill -HUP $MAINPID",
    target_run_binary: "daed",
    target_exec_start_pre: "/usr/bin/daed validate -c /etc/daed/",
    target_exec_start: "/usr/bin/daed run -c /etc/daed/",
    target_exec_reload: "/bin/kill -HUP $MAINPID",
    backup_service_file_name: "daed.service",
    backup_binary_file_name: "usr-bin-daed",
    backup_local_binary_file_name: "usr-local-bin-daed",
};

impl ProductPathLayout {
    pub(super) fn from_kind(kind: Option<&str>) -> Self {
        match kind {
            Some("daed") => DAED_LAYOUT,
            _ => DAE_LAYOUT,
        }
    }

    pub(super) fn from_report(report: &serde_json::Value) -> Self {
        Self::from_kind(report["service"]["service_contract_kind"].as_str())
    }

    pub(super) fn from_service_file(path: &Path) -> Self {
        let Ok(text) = fs::read_to_string(path) else {
            return DAE_LAYOUT;
        };
        if text.contains("/usr/bin/daed") || text.contains("daed.service") {
            DAED_LAYOUT
        } else {
            DAE_LAYOUT
        }
    }

    pub(super) fn service_manager_commands(self) -> [&'static str; 3] {
        match self.kind {
            "daed" => [
                "systemctl daemon-reload",
                "systemctl restart daed.service",
                "systemctl status daed.service --no-pager",
            ],
            _ => [
                "systemctl daemon-reload",
                "systemctl restart dae.service",
                "systemctl status dae.service --no-pager",
            ],
        }
    }

    pub(super) fn post_smoke_commands(self) -> [&'static str; 3] {
        match self.kind {
            "daed" => [
                "daed validate -c /etc/daed/",
                "daed run -c /etc/daed/",
                "systemctl kill -s HUP daed.service",
            ],
            _ => [
                "dae-daemon-optin validate -c /etc/dae/config.dae",
                "dae-daemon-optin run --disable-timestamp -c /etc/dae/config.dae --exit-after-ready",
                "dae-daemon-optin reload $MAINPID",
            ],
        }
    }

    pub(super) fn validation_checklist(self) -> [&'static str; 3] {
        match self.kind {
            "daed" => [
                "validate using the frozen installed daed target and materialized /etc/daed",
                "run ready using the frozen installed daed target and materialized /etc/daed",
                "validate reload against the newly installed daed service process",
            ],
            _ => [
                "validate using the frozen installed dae target and materialized /etc/dae/config.dae",
                "run ready using the frozen installed dae target and materialized /etc/dae/config.dae",
                "validate reload against the newly installed dae service process",
            ],
        }
    }

    pub(super) fn service_diff(self, service_file: &str) -> String {
        if self.kind == "daed" {
            return format!(
                "--- {service_file}.current\n+++ {service_file}.target\n@@ product command freeze\n ExecStartPre={}\n ExecStart={}\n ExecReload={}\n",
                self.current_exec_start_pre, self.current_exec_start, self.current_exec_reload
            );
        }
        format!(
            "--- {service_file}.current\n+++ {service_file}.target\n@@ production run command replacement\n-ExecStartPre={}\n+ExecStartPre={}\n-ExecStart={}\n+ExecStart={}\n-ExecReload={}\n+ExecReload={}\n",
            self.current_exec_start_pre,
            self.target_exec_start_pre,
            self.current_exec_start,
            self.target_exec_start,
            self.current_exec_reload,
            self.target_exec_reload
        )
    }
}
