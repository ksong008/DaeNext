use super::*;
use aya::programs::{CgroupSock, ProgramError};
use std::process::{Command, Stdio};

struct CgroupCoexistenceFixture {
    cgroup_paths: Vec<PathBuf>,
    pin_roots: Vec<PathBuf>,
    object: PathBuf,
}

impl CgroupCoexistenceFixture {
    fn new(cgroup_root: &Path) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let suffix = format!("{}-{nonce}", std::process::id());
        let cgroup_paths = ["empty", "multi", "single"]
            .map(|mode| cgroup_root.join(format!("dae-cgroup-fixture-{mode}-{suffix}")))
            .into_iter()
            .collect::<Vec<_>>();
        for path in &cgroup_paths {
            std::fs::create_dir(path).unwrap_or_else(|error| {
                panic!(
                    "create cgroup coexistence fixture {}: {error}",
                    path.display()
                )
            });
        }
        let object = temp_path(&format!("dae-cgroup-fixture-{suffix}.o"));
        let pin_roots = (0..4)
            .map(|index| {
                default_bpffs_mount()
                    .unwrap()
                    .join(format!("dae-cgroup-fixture-{suffix}-{index}"))
            })
            .collect::<Vec<_>>();
        for path in &pin_roots {
            std::fs::create_dir_all(path).unwrap();
        }
        Self {
            cgroup_paths,
            pin_roots,
            object,
        }
    }

    fn empty(&self) -> &Path {
        &self.cgroup_paths[0]
    }

    fn multi(&self) -> &Path {
        &self.cgroup_paths[1]
    }

    fn single(&self) -> &Path {
        &self.cgroup_paths[2]
    }
}

impl Drop for CgroupCoexistenceFixture {
    fn drop(&mut self) {
        for cgroup in &self.cgroup_paths {
            for pin_root in &self.pin_roots {
                let program = pin_root.join("sock-create");
                let _ = Command::new("bpftool")
                    .args(["cgroup", "detach"])
                    .arg(cgroup)
                    .arg("cgroup_inet_sock_create")
                    .arg("pinned")
                    .arg(program)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        for root in &self.pin_roots {
            let _ = std::fs::remove_dir_all(root);
        }
        let _ = std::fs::remove_file(&self.object);
        for path in self.cgroup_paths.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }
}

#[test]
fn cgroup_empty_multi_single_coexistence_fixture_is_env_gated_and_cleans_up() {
    if std::env::var_os("DAE_RUN_CGROUP_COEXISTENCE_FIXTURE").is_none() {
        return;
    }

    let cgroup_root =
        detect_cgroup2_mount().expect("cgroup coexistence fixture requires cgroup v2");
    let fixture = CgroupCoexistenceFixture::new(&cgroup_root);
    let repo_root = dae_golden::repo_root_from_manifest().unwrap();
    build_aya_compatible_bpf_object(&repo_root, &fixture.object);

    let empty = run_bpftool(["cgroup", "show"], [fixture.empty()]);
    assert!(empty.status.success(), "{}", empty.stderr);
    assert!(empty.stdout.trim().is_empty(), "{}", empty.stdout);

    let mut multi_first = load_fixture_object(&fixture.object, &fixture.pin_roots[0]);
    let mut multi_second = load_fixture_object(&fixture.object, &fixture.pin_roots[1]);
    let multi_first_pin = fixture.pin_roots[0].join("sock-create");
    let multi_second_pin = fixture.pin_roots[1].join("sock-create");
    pin_sock_create(&mut multi_first, &multi_first_pin);
    pin_sock_create(&mut multi_second, &multi_second_pin);
    assert_bpftool_success(attach_command(fixture.multi(), &multi_first_pin, true));
    assert_bpftool_success(attach_command(fixture.multi(), &multi_second_pin, true));
    let multi_show = run_bpftool(["cgroup", "show"], [fixture.multi()]);
    assert!(multi_show.status.success(), "{}", multi_show.stderr);
    assert_eq!(
        multi_show
            .stdout
            .lines()
            .filter(|line| line.contains("sock_create"))
            .count(),
        2,
        "{}",
        multi_show.stdout
    );
    assert_bpftool_success(detach_command(fixture.multi(), &multi_second_pin));
    assert_bpftool_success(detach_command(fixture.multi(), &multi_first_pin));

    let mut single_first = load_fixture_object(&fixture.object, &fixture.pin_roots[2]);
    let mut single_second = load_fixture_object(&fixture.object, &fixture.pin_roots[3]);
    let single_first_pin = fixture.pin_roots[2].join("sock-create");
    let single_second_pin = fixture.pin_roots[3].join("sock-create");
    pin_sock_create(&mut single_first, &single_first_pin);
    pin_sock_create(&mut single_second, &single_second_pin);
    assert_bpftool_success(attach_command(fixture.single(), &single_first_pin, false));
    let incompatible = attach_command(fixture.single(), &single_second_pin, true);
    assert!(!incompatible.status.success(), "{}", incompatible.stdout);
    assert!(!incompatible.stderr.trim().is_empty());
    assert_bpftool_success(detach_command(fixture.single(), &single_first_pin));

    drop(single_second);
    drop(single_first);
    drop(multi_second);
    drop(multi_first);
    let paths = fixture.cgroup_paths.clone();
    drop(fixture);
    assert!(paths.iter().all(|path| !path.exists()));
}

fn load_fixture_object(object: &Path, pin_root: &Path) -> AyaUserspaceLoadedObject {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: std::process::id(),
        dae0_ifindex: 1,
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    });
    load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object,
        param: Some(param),
        map_pin_path: Some(pin_root),
        allow_unsupported_maps: true,
        allowed_unsupported_map_names: DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
        target_btf_required: false,
    })
    .expect("load cgroup coexistence fixture object")
}

fn pin_sock_create(loaded: &mut AyaUserspaceLoadedObject, path: &Path) {
    let line = &dae_cgroup_attach_matrix()[0];
    let program = loaded
        .ebpf
        .program_mut(line.program_name)
        .expect("cgroup coexistence sock_create program");
    let program: &mut CgroupSock = program
        .try_into()
        .unwrap_or_else(|error| panic!("convert cgroup coexistence sock program: {error:?}"));
    match program.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(error) => panic!("load cgroup coexistence sock program: {error:?}"),
    }
    program.pin(path).unwrap_or_else(|error| {
        panic!(
            "pin cgroup coexistence sock program {}: {error}",
            path.display()
        )
    });
}

struct BpftoolOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn attach_command(cgroup: &Path, program: &Path, multi: bool) -> BpftoolOutput {
    let mut command = Command::new("bpftool");
    command
        .args(["cgroup", "attach"])
        .arg(cgroup)
        .arg("cgroup_inet_sock_create")
        .arg("pinned")
        .arg(program);
    if multi {
        command.arg("multi");
    }
    command_output(command)
}

fn detach_command(cgroup: &Path, program: &Path) -> BpftoolOutput {
    let mut command = Command::new("bpftool");
    command
        .args(["cgroup", "detach"])
        .arg(cgroup)
        .arg("cgroup_inet_sock_create")
        .arg("pinned")
        .arg(program);
    command_output(command)
}

fn run_bpftool<const N: usize, const M: usize>(
    args: [&str; N],
    paths: [&Path; M],
) -> BpftoolOutput {
    let mut command = Command::new("bpftool");
    command.args(args);
    for path in paths {
        command.arg(path);
    }
    command_output(command)
}

fn command_output(mut command: Command) -> BpftoolOutput {
    let output = command
        .output()
        .expect("run bpftool cgroup fixture command");
    BpftoolOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn assert_bpftool_success(output: BpftoolOutput) {
    assert!(
        output.status.success(),
        "bpftool failed: stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
}
