#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdContract {
    pub type_notify: bool,
    pub user_root: bool,
    pub limit_nproc: &'static str,
    pub limit_nofile: &'static str,
    pub exec_start_pre: &'static str,
    pub exec_start: &'static str,
    pub exec_reload: &'static str,
    pub restart: &'static str,
    pub timeout_start_sec: &'static str,
    pub after: &'static str,
    pub wants: &'static str,
    pub after_install_daemon_reload: bool,
    pub after_install_restart_active: bool,
    pub after_remove_daemon_reload: bool,
    pub validate_exec_start_pre: bool,
    pub run_systemd_notify: bool,
    pub reload_pid_progress: bool,
}

pub fn systemd_contract() -> SystemdContract {
    SystemdContract {
        type_notify: true,
        user_root: true,
        limit_nproc: "512",
        limit_nofile: "1048576",
        exec_start_pre: "/usr/bin/dae validate -c /etc/dae/config.dae",
        exec_start: "/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae",
        exec_reload: "/usr/bin/dae reload $MAINPID",
        restart: "on-abnormal",
        timeout_start_sec: "120",
        after: "network-online.target docker.service systemd-sysctl.service",
        wants: "network-online.target",
        after_install_daemon_reload: true,
        after_install_restart_active: true,
        after_remove_daemon_reload: true,
        validate_exec_start_pre: true,
        run_systemd_notify: true,
        reload_pid_progress: true,
    }
}
