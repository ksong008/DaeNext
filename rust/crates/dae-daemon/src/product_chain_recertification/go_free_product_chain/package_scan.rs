use super::*;
pub(crate) fn default_product_package_scan_json(
    options: &ProductChainRecertificationOptions,
) -> Value {
    let makefile = options.daed_repo.join("Makefile");
    let dockerfile = options.daed_repo.join("Dockerfile");
    let publish_dockerfile = options.daed_repo.join("publish.Dockerfile");
    let integration_workflow = options.daed_repo.join(".github/workflows/daed2.0.yml");
    let release_workflow = options
        .daed_repo
        .join(".github/workflows/release-please.yml");
    let linux_test_workflow = options
        .daed_repo
        .join(".github/workflows/test-linux-amd64v3.yml");

    let makefile_text = read_text(&makefile);
    let dockerfile_text = read_text(&dockerfile);
    let publish_dockerfile_text = read_text(&publish_dockerfile);
    let integration_text = read_text(&integration_workflow);
    let release_text = read_text(&release_workflow);
    let linux_test_text = read_text(&linux_test_workflow);

    let make_default_rust_native = makefile_text.contains("daed: daed-rust-native")
        && makefile_text.contains("cargo build $(RUST_DAED_BUILD_ARGS)")
        && makefile_text.contains("daed-go-rollback:");
    let make_go_rollback_explicit = makefile_text.contains("daed-go-rollback:")
        && makefile_text.contains("$(MAKE) OUTPUT=../$(OUTPUT)")
        && makefile_text.contains(" bundle");
    let make_default_uses_wing_bundle =
        makefile_rule(&makefile_text, "daed").contains("bundle") && !make_default_rust_native;
    let rust_native_rule = makefile_rule(&makefile_text, "daed-rust-native");
    let default_build_uses_go_bpf_generator = rust_native_rule.contains("$(DAE_CORE_BPF_OBJECT)")
        || rust_native_rule.contains("make ebpf")
        || rust_native_rule.contains("$(MAKE) ebpf");
    let explicit_legacy_bpf_generator_present = makefile_text.contains("$(DAE_CORE_BPF_OBJECT):")
        && makefile_text.contains("cd wing/dae-core")
        && makefile_text.contains("$(MAKE) ebpf");

    let docker_default_rust_native = dockerfile_text.contains("FROM rust:")
        && dockerfile_text.contains("daed-rust-native")
        && dockerfile_text.contains("/usr/share/daed/web")
        && dockerfile_text.contains("daed-docker-entrypoint");
    let docker_default_uses_wing_bundle = dockerfile_text.contains("WORKDIR /build/wing")
        || dockerfile_text.contains("make APPNAME=daed") && dockerfile_text.contains(" bundle");

    let publish_docker_default_rust_native = publish_dockerfile_text.contains("FROM rust:")
        && publish_dockerfile_text.contains("daed-rust-native")
        && publish_dockerfile_text.contains("/usr/share/daed/web")
        && publish_dockerfile_text.contains("daed-docker-entrypoint");
    let publish_docker_default_uses_wing_bundle = publish_dockerfile_text
        .contains("WORKDIR /build/wing")
        || publish_dockerfile_text.contains("make APPNAME=daed")
            && publish_dockerfile_text.contains(" bundle");

    let integration_default_rust_native = integration_text.contains("Build Rust native daed")
        && integration_text.contains("DAED_SKIP_WEB_BUILD")
        && integration_text.contains("make")
        && !integration_text.contains("working-directory: wing")
        && !integration_text.contains("make bundle");
    let release_default_rust_native = release_text.contains("DAED_SKIP_WEB_BUILD")
        && release_text.contains("RUSTFLAGS")
        && release_text.contains("./web=/usr/share/daed/web")
        && !release_text.contains("make bundle");
    let release_source_archive_uses_wing_vendor = release_text.contains("Download wing vendor")
        && release_text.contains("working-directory: wing");
    let linux_test_default_rust_native = linux_test_text.contains("Build Rust native daed")
        && linux_test_text.contains("DAED_SKIP_WEB_BUILD")
        && linux_test_text.contains("make")
        && !linux_test_text.contains("working-directory: wing")
        && !linux_test_text.contains("make bundle");

    let go_product_shell_retired_from_default_package = make_default_rust_native
        && make_go_rollback_explicit
        && !make_default_uses_wing_bundle
        && docker_default_rust_native
        && !docker_default_uses_wing_bundle
        && publish_docker_default_rust_native
        && !publish_docker_default_uses_wing_bundle
        && integration_default_rust_native
        && release_default_rust_native
        && !release_source_archive_uses_wing_vendor
        && linux_test_default_rust_native
        && !default_build_uses_go_bpf_generator;
    let default_product_package_go_free =
        go_product_shell_retired_from_default_package && !default_build_uses_go_bpf_generator;
    let mut blockers = Vec::new();
    if !make_default_rust_native {
        blockers.push("C10 daed Makefile default target is not Rust native".to_owned());
    }
    if !make_go_rollback_explicit {
        blockers.push("C10 Go rollback bundle target is not explicit".to_owned());
    }
    if make_default_uses_wing_bundle {
        blockers.push("C10 daed Makefile default target still uses wing bundle".to_owned());
    }
    if !docker_default_rust_native || docker_default_uses_wing_bundle {
        blockers.push("C10 Dockerfile default image path is not Rust native".to_owned());
    }
    if !publish_docker_default_rust_native || publish_docker_default_uses_wing_bundle {
        blockers.push("C10 publish Dockerfile default image path is not Rust native".to_owned());
    }
    if !integration_default_rust_native {
        blockers.push("C10 integration workflow default build path is not Rust native".to_owned());
    }
    if !release_default_rust_native {
        blockers
            .push("C10 release workflow default build/package path is not Rust native".to_owned());
    }
    if release_source_archive_uses_wing_vendor {
        blockers.push(
            "C10 release source archive still vendors Go modules from the default path".to_owned(),
        );
    }
    if !linux_test_default_rust_native {
        blockers.push("C10 linux test workflow default build path is not Rust native".to_owned());
    }
    if default_build_uses_go_bpf_generator {
        blockers.push(
            "C10 default package build still depends on Go-generated kernel BPF object".to_owned(),
        );
    }

    json!({
        "name": "default-product-package-scan",
        "status": if default_product_package_go_free { "pass" } else { "blocked" },
        "default_product_package_go_free": default_product_package_go_free,
        "go_product_shell_retired_from_default_package": go_product_shell_retired_from_default_package,
        "default_build_uses_go_bpf_generator": default_build_uses_go_bpf_generator,
        "explicit_legacy_bpf_generator_present": explicit_legacy_bpf_generator_present,
        "makefile": {
            "path": path_string(&makefile),
            "exists": makefile.is_file(),
            "default_rust_native": make_default_rust_native,
            "go_rollback_explicit": make_go_rollback_explicit,
            "default_uses_wing_bundle": make_default_uses_wing_bundle,
        },
        "dockerfile": {
            "path": path_string(&dockerfile),
            "exists": dockerfile.is_file(),
            "default_rust_native": docker_default_rust_native,
            "default_uses_wing_bundle": docker_default_uses_wing_bundle,
        },
        "publish_dockerfile": {
            "path": path_string(&publish_dockerfile),
            "exists": publish_dockerfile.is_file(),
            "default_rust_native": publish_docker_default_rust_native,
            "default_uses_wing_bundle": publish_docker_default_uses_wing_bundle,
        },
        "workflows": {
            "integration": {
                "path": path_string(&integration_workflow),
                "exists": integration_workflow.is_file(),
                "default_rust_native": integration_default_rust_native,
            },
            "release": {
                "path": path_string(&release_workflow),
                "exists": release_workflow.is_file(),
                "default_rust_native": release_default_rust_native,
                "source_archive_uses_wing_vendor": release_source_archive_uses_wing_vendor,
            },
            "linux_test": {
                "path": path_string(&linux_test_workflow),
                "exists": linux_test_workflow.is_file(),
                "default_rust_native": linux_test_default_rust_native,
            },
        },
        "blockers": blockers,
    })
}
