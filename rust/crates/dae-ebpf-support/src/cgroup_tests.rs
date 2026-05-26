#[cfg(feature = "aya-loader")]
use std::path::Path;
use std::path::PathBuf;

use crate::*;

#[test]
fn dae_cgroup_attach_matrix_matches_go_attachcgroup_order() {
    let matrix = dae_cgroup_attach_matrix();
    assert_eq!(matrix.len(), 6);
    assert_eq!(
        matrix.iter().map(|line| line.role).collect::<Vec<_>>(),
        vec![
            DaeCgroupAttachRole::SockCreate,
            DaeCgroupAttachRole::SockRelease,
            DaeCgroupAttachRole::Connect4,
            DaeCgroupAttachRole::Connect6,
            DaeCgroupAttachRole::Sendmsg4,
            DaeCgroupAttachRole::Sendmsg6,
        ]
    );

    assert_cgroup_line(
        &matrix[0],
        DaeCgroupAttachRole::SockCreate,
        "cgroup/sock_create",
        "tproxy_wan_cg_sock_create",
        "AttachCGroupInetSockCreate",
        DaeCgroupProgramKind::Sock,
    );
    assert_cgroup_line(
        &matrix[1],
        DaeCgroupAttachRole::SockRelease,
        "cgroup/sock_release",
        "tproxy_wan_cg_sock_release",
        "AttachCgroupInetSockRelease",
        DaeCgroupProgramKind::Sock,
    );
    assert_cgroup_line(
        &matrix[2],
        DaeCgroupAttachRole::Connect4,
        "cgroup/connect4",
        "tproxy_wan_cg_connect4",
        "AttachCGroupInet4Connect",
        DaeCgroupProgramKind::SockAddr,
    );
    assert_cgroup_line(
        &matrix[3],
        DaeCgroupAttachRole::Connect6,
        "cgroup/connect6",
        "tproxy_wan_cg_connect6",
        "AttachCGroupInet6Connect",
        DaeCgroupProgramKind::SockAddr,
    );
    assert_cgroup_line(
        &matrix[4],
        DaeCgroupAttachRole::Sendmsg4,
        "cgroup/sendmsg4",
        "tproxy_wan_cg_sendmsg4",
        "AttachCGroupUDP4Sendmsg",
        DaeCgroupProgramKind::SockAddr,
    );
    assert_cgroup_line(
        &matrix[5],
        DaeCgroupAttachRole::Sendmsg6,
        "cgroup/sendmsg6",
        "tproxy_wan_cg_sendmsg6",
        "AttachCGroupUDP6Sendmsg",
        DaeCgroupProgramKind::SockAddr,
    );
    assert!(
        matrix
            .iter()
            .all(|line| line.attach_mode == "single" && line.link_lifetime_owned_by_backend)
    );
}

#[test]
fn cgroup2_mount_parser_matches_go_first_found_semantics() {
    let mounts = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup cgroup rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /other cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
";
    assert_eq!(
        detect_cgroup2_mount_from_proc_mounts(mounts),
        Some(PathBuf::from("/sys/fs/cgroup/unified"))
    );
    assert_eq!(
        detect_cgroup2_mount_from_proc_mounts("proc /proc proc rw 0 0"),
        None
    );
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_cgroup_attach_detach_smoke_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_CGROUP_ATTACH_SMOKE").is_none() {
        return;
    }

    let cgroup_root = match detect_cgroup2_mount() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("skip aya cgroup attach smoke: {err}");
            return;
        }
    };
    let cgroup_path = cgroup_root.join(format!("dae-aya-cgroup-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir(&cgroup_path);
    if let Err(err) = std::fs::create_dir(&cgroup_path) {
        eprintln!(
            "skip aya cgroup attach smoke: create {} failed: {err}",
            cgroup_path.display()
        );
        return;
    }

    let root = dae_golden::repo_root_from_manifest().unwrap();
    let aya_object = temp_path("dae-aya-cgroup-bpf_bpfel.o");
    build_aya_compatible_bpf_object(&root, &aya_object);
    let pin_root = default_bpffs_mount()
        .unwrap()
        .join(format!("dae-aya-cgroup-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&pin_root).unwrap();

    let result = run_aya_cgroup_attach_detach_smoke(&aya_object, &pin_root, &cgroup_path);

    let _ = std::fs::remove_dir_all(&pin_root);
    let _ = std::fs::remove_file(&aya_object);
    let _ = std::fs::remove_dir(&cgroup_path);

    let reports =
        result.unwrap_or_else(|err| panic!("aya cgroup attach/detach smoke failed: {err}"));
    assert_eq!(reports.len(), 6);
    for (report, line) in reports.iter().zip(dae_cgroup_attach_matrix()) {
        assert_eq!(report.role, line.role);
        assert_eq!(report.cgroup_path, cgroup_path);
        assert_eq!(report.program_name, line.program_name);
        assert_eq!(report.section, line.section);
        assert_eq!(report.program_kind, line.aya_program_kind);
        assert_eq!(report.attach_mode, "single");
        assert!(report.loaded);
        assert!(report.attached);
        assert!(report.detached);
        assert!(report.link_lifetime_owned_by_backend);
    }
}

fn assert_cgroup_line(
    line: &DaeCgroupAttachLine,
    role: DaeCgroupAttachRole,
    section: &'static str,
    program_name: &'static str,
    go_attach_type: &'static str,
    kind: DaeCgroupProgramKind,
) {
    assert_eq!(line.role, role);
    assert_eq!(line.section, section);
    assert_eq!(line.program_name, program_name);
    assert_eq!(line.go_attach_type, go_attach_type);
    assert_eq!(line.aya_program_kind, kind);
}

#[cfg(feature = "aya-loader")]
fn run_aya_cgroup_attach_detach_smoke(
    aya_object: &Path,
    pin_root: &Path,
    cgroup_path: &Path,
) -> Result<Vec<AyaCgroupAttachDetachReport>, String> {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: std::process::id(),
        dae0_ifindex: 1,
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    let mut loaded = load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: aya_object,
        param: Some(param),
        map_pin_path: Some(pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    })?;
    dae_cgroup_attach_matrix()
        .iter()
        .map(|line| load_attach_detach_aya_cgroup_program(&mut loaded, line, cgroup_path))
        .collect()
}

#[cfg(feature = "aya-loader")]
fn build_aya_compatible_bpf_object(root: &Path, output: &Path) {
    let clang = std::env::var("DAE_BPF_CLANG").unwrap_or_else(|_| "clang".to_owned());
    let include_dir = root.join("control/kern/headers");
    let source = root.join("control/kern/tproxy.c");
    let output = std::process::Command::new(&clang)
        .args([
            "-g",
            "-O2",
            "-Wall",
            "-Werror",
            "-DMAX_MATCH_SET_LEN=1024",
            "-DDAE_AYA_EBPF_OBJECT",
            "-target",
            "bpfel",
            "-c",
        ])
        .arg(&source)
        .arg("-I")
        .arg(&include_dir)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute {clang}: {err}"));
    if !output.status.success() {
        panic!(
            "failed to build Aya-compatible eBPF object: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(feature = "aya-loader")]
fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}-{name}", std::process::id()))
}
