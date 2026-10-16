use super::support::FreshProductState;
use super::*;

#[test]
fn changed_external_ca_prevents_unchanged_reload_coalescing() {
    const CHILD_BUNDLE: &str = "DAED_TEST_RELOAD_CA_BUNDLE";
    let Some(bundle) = std::env::var_os(CHILD_BUNDLE) else {
        // Isolate SSL_CERT_FILE and the process-global trust cache from every
        // other test. The child receives its environment before it starts.
        let product = FreshProductState::new("reload-ca-parent");
        let bundle = product.root().join("roots.pem");
        let identity =
            dae_outbound::shared_transport::test_support::self_signed_tls_identity(&["localhost"])
                .unwrap();
        fs::write(&bundle, identity.certificate.to_pem().unwrap()).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daed_product::tests::runtime_trust_reload::changed_external_ca_prevents_unchanged_reload_coalescing",
                "--test-threads=1",
            ])
            .env(CHILD_BUNDLE, &bundle)
            .env("SSL_CERT_FILE", &bundle)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    };
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("reload-ca-child");
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = ProductRuntimeManager::new();
        dae_tls::system_ca_snapshot().unwrap();
        let reload = || {
            coordinate_runtime_reload(
                &runtime,
                product.state(),
                Some(&config_dir),
                RuntimeApplyIntent::ApiReload,
                &[],
                AllocatorReclaimReason::ReloadCompleted,
            )
            .unwrap()
        };
        assert!(reload().applied);
        assert!(reload().coalesced, "identical CA should still coalesce");
        let mut changed = fs::read(&bundle).unwrap();
        changed.extend_from_slice(b"\n");
        fs::write(&bundle, changed).unwrap();
        let updated = reload();
        assert!(updated.applied && !updated.coalesced);
        assert_eq!(runtime.summary()["reloadCount"], json!(2));
        fs::remove_file(&bundle).unwrap();
        let missing = reload();
        assert!(missing.applied && !missing.coalesced);
        assert_eq!(runtime.summary()["reloadCount"], json!(3));
        assert!(reload().coalesced, "unchanged missing CA should coalesce");
    });
}
