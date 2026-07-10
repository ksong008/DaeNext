use super::*;
use std::path::PathBuf;

pub(crate) struct FreshProductApi {
    root: PathBuf,
    port: u16,
    token: String,
    child: Option<Child>,
}

impl FreshProductApi {
    pub(crate) fn spawn(scope: &str) -> Self {
        let root = temp_dir(scope);
        let web = root.join("web");
        fs::create_dir_all(&web).unwrap();
        fs::write(
            web.join("index.html"),
            "<!doctype html><title>fixture</title>",
        )
        .unwrap();
        let port = free_port();
        let listen = loopback_listen_addr(port);
        let mut child = Command::new(binary())
            .args(["run", "-c"])
            .arg(&root)
            .args(["--listen", &listen, "--web-root"])
            .arg(&web)
            .arg("--control")
            .arg(root.join("control.sock"))
            .env("PRODUCT_RUNTIME_FAKE_START", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_http(port, "/api/health", &mut child);

        let username = format!("fixture-{}", fastrand::u64(..));
        let create = http_request(
            port,
            "POST",
            "/api/auth/users",
            Some(&format!(
                r#"{{"username":"{username}","password":"fixture-pass-123"}}"#
            )),
            None,
        );
        assert!(create.contains("201 Created"), "{create}");
        let token = json_body(&create)["token"].as_str().unwrap().to_owned();
        Self {
            root,
            port,
            token,
            child: Some(child),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.root.join("daed.db")
    }

    pub(crate) fn generated_config_path(&self) -> PathBuf {
        self.root.join("runtime/generated.dae")
    }

    pub(crate) fn request(&self, method: &str, path: &str, body: Option<&str>) -> String {
        http_request(self.port, method, path, body, Some(&self.token))
    }

    pub(crate) fn request_json(&self, method: &str, path: &str, body: Option<&str>) -> Value {
        json_body(&self.request(method, path, body))
    }

    pub(crate) fn seed_selected_resources(&self) {
        for (collection, body) in [
            (
                "configs",
                r#"{"name":"fixture-global","global":"global {}"}"#,
            ),
            ("dns", r#"{"name":"fixture-dns","dns":"dns {}"}"#),
            (
                "routings",
                r#"{"name":"fixture-routing","routing":"routing { fallback: direct }"}"#,
            ),
        ] {
            let created = self.request_json("POST", &format!("/api/{collection}"), Some(body));
            let id = created["id"].as_i64().unwrap();
            let selected = self.request(
                "POST",
                &format!("/api/{collection}/{id}/select"),
                Some("{}"),
            );
            assert!(selected.contains("200 OK"), "{selected}");
        }
    }

    pub(crate) fn reload(&self) -> Value {
        self.request_json("POST", "/api/runtime/reload", Some(r#"{"dry":false}"#))
    }

    pub(crate) fn interrupt(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn shutdown(&mut self) {
        if self.child.is_some() {
            let _ = try_http_request(
                self.port,
                "POST",
                "/api/runtime/stop",
                Some("{}"),
                Some(&self.token),
            );
        }
        self.interrupt();
        if self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

impl Drop for FreshProductApi {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::yield_now();
    }
}

#[test]
fn fresh_product_api_covers_auth_materialize_reload_stop_and_cleanup() {
    let root;
    {
        let fixture = FreshProductApi::spawn("fresh-state-lifecycle");
        root = fixture.root().to_path_buf();
        fixture.seed_selected_resources();
        let reload = fixture.reload();
        assert_eq!(reload["applied"], Value::from(1), "{reload}");
        assert!(fixture.state_path().is_file());
        assert!(fixture.generated_config_path().is_file());
        let stop = fixture.request_json("POST", "/api/runtime/stop", Some("{}"));
        assert_eq!(stop["stopped"], Value::Bool(true), "{stop}");
    }
    assert!(!root.exists());
}

#[test]
fn fresh_product_api_cleans_after_interrupted_process() {
    let root;
    {
        let mut fixture = FreshProductApi::spawn("fresh-state-interruption");
        root = fixture.root().to_path_buf();
        fixture.interrupt();
    }
    assert!(!root.exists());
}

#[test]
fn fresh_product_api_cleans_after_bounded_wait_timeout() {
    let root;
    {
        let fixture = FreshProductApi::spawn("fresh-state-timeout");
        root = fixture.root().to_path_buf();
        assert!(!wait_until(Duration::from_millis(2), || false));
    }
    assert!(!root.exists());
}
