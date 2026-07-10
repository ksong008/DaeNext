use super::*;

pub(crate) struct FreshProductState {
    root: PathBuf,
    state: PathBuf,
}

impl FreshProductState {
    pub(crate) fn new(scope: &str) -> Self {
        let safe_scope = scope
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let root = std::env::temp_dir().join(format!(
            "daed-product-fixture-{safe_scope}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        let state = root.join("daed.db");
        ensure_state_schema(&state).expect("create isolated product state");
        Self { root, state }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn state(&self) -> &Path {
        &self.state
    }

    pub(crate) fn connection(&self) -> Connection {
        open_state_connection(&self.state).expect("open isolated product state")
    }

    pub(crate) fn seed_selected_resources(&self) {
        let conn = self.connection();
        conn.execute_batch(
            r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'fixture-global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'fixture-dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'fixture-routing', 'routing { fallback: direct }', 1, 1);
            "#,
        )
        .expect("seed selected product resources");
    }
}

impl Drop for FreshProductState {
    fn drop(&mut self) {
        if self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
fn fresh_product_state_is_isolated_and_cleans_up_after_success() {
    let root;
    {
        let fixture = FreshProductState::new("success-cleanup");
        root = fixture.root().to_path_buf();
        fixture.seed_selected_resources();
        assert!(fixture.state().is_file());
        assert_eq!(
            fixture
                .connection()
                .query_row("SELECT COUNT(*) FROM configs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    assert!(!root.exists());
}

#[test]
fn fresh_product_state_cleans_up_during_unwind() {
    let root = Arc::new(Mutex::new(None::<PathBuf>));
    let root_for_unwind = Arc::clone(&root);
    let result = std::panic::catch_unwind(move || {
        let fixture = FreshProductState::new("unwind-cleanup");
        *root_for_unwind.lock().unwrap() = Some(fixture.root().to_path_buf());
        panic!("fixture interruption");
    });
    assert!(result.is_err());
    let root = root.lock().unwrap().clone().unwrap();
    assert!(!root.exists());
}
