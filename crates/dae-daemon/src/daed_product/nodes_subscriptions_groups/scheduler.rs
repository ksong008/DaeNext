use super::*;
#[cfg(test)]
use dae_product_control::subscription::InvalidCronLogTracker;
use dae_product_control::subscription::{
    SubscriptionSchedulerCallbacks, SubscriptionSchedulerRuntimeApply,
};

pub(crate) use dae_product_control::subscription::validate_subscription_cron_expression;

pub(crate) fn notify_subscription_scheduler() {
    dae_product_control::subscription::notify_subscription_scheduler();
}

pub(crate) fn start_subscription_scheduler(
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
    control_runtime: Arc<ProductControlRuntime>,
) -> io::Result<SubscriptionSchedulerHandle> {
    let callbacks = Arc::new(OwnedDaemonSubscriptionSchedulerCallbacks {
        control_runtime: Arc::clone(&control_runtime),
        runtime: Arc::clone(&runtime),
    });
    dae_product_control::subscription::start_subscription_scheduler(state, config_dir, callbacks)
}

pub(crate) use dae_product_control::subscription::SubscriptionSchedulerHandle;

#[cfg(test)]
pub(crate) fn refresh_due_subscriptions_for_scheduler(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    now_unix: u64,
) -> io::Result<Value> {
    let mut invalid_cron = InvalidCronLogTracker::default();
    let control_runtime = product_test_control_runtime();
    refresh_due_subscriptions_for_scheduler_with_tracker(
        &control_runtime,
        state,
        config_dir,
        runtime,
        now_unix,
        &mut invalid_cron,
    )
}

#[cfg(test)]
fn refresh_due_subscriptions_for_scheduler_with_tracker(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    now_unix: u64,
    invalid_cron: &mut InvalidCronLogTracker,
) -> io::Result<Value> {
    let callbacks = DaemonSubscriptionSchedulerCallbacks {
        control_runtime,
        runtime,
    };
    dae_product_control::subscription::refresh_due_subscriptions_with_callbacks(
        &callbacks,
        state,
        config_dir,
        now_unix,
        invalid_cron,
    )
}

#[cfg(test)]
struct DaemonSubscriptionSchedulerCallbacks<'a> {
    control_runtime: &'a ProductControlRuntime,
    runtime: &'a ProductRuntimeManager,
}

struct OwnedDaemonSubscriptionSchedulerCallbacks {
    control_runtime: Arc<ProductControlRuntime>,
    runtime: Arc<ProductRuntimeManager>,
}

#[cfg(test)]
impl SubscriptionSchedulerCallbacks for DaemonSubscriptionSchedulerCallbacks<'_> {
    fn refresh_subscription(
        &self,
        state: &Path,
        config_dir: &Path,
        subscription_id: i64,
    ) -> io::Result<Value> {
        refresh_subscription_from_remote(self.control_runtime, state, config_dir, subscription_id)
    }

    fn apply_runtime(
        &self,
        state: &Path,
        config_dir: &Path,
        requested: bool,
    ) -> SubscriptionSchedulerRuntimeApply {
        let result = apply_runtime_after_subscription_change(
            state,
            config_dir,
            self.runtime,
            requested,
            "subscription-scheduler",
        );
        SubscriptionSchedulerRuntimeApply {
            requested: result.requested,
            applied: result.applied,
            report: result.report.unwrap_or(Value::Null),
            error: result.error,
        }
    }

    fn append_log(&self, config_dir: &Path, state: &Path, level: &str, message: &str) {
        let _ = append_log_for_config(config_dir, state, level, message);
    }
}

impl SubscriptionSchedulerCallbacks for OwnedDaemonSubscriptionSchedulerCallbacks {
    fn refresh_subscription(
        &self,
        state: &Path,
        config_dir: &Path,
        subscription_id: i64,
    ) -> io::Result<Value> {
        refresh_subscription_from_remote(&self.control_runtime, state, config_dir, subscription_id)
    }

    fn apply_runtime(
        &self,
        state: &Path,
        config_dir: &Path,
        requested: bool,
    ) -> SubscriptionSchedulerRuntimeApply {
        let result = apply_runtime_after_subscription_change(
            state,
            config_dir,
            &self.runtime,
            requested,
            "subscription-scheduler",
        );
        SubscriptionSchedulerRuntimeApply {
            requested: result.requested,
            applied: result.applied,
            report: result.report.unwrap_or(Value::Null),
            error: result.error,
        }
    }

    fn append_log(&self, config_dir: &Path, state: &Path, level: &str, message: &str) {
        let _ = append_log_for_config(config_dir, state, level, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_tick_refreshes_due_subscription_from_remote() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-scheduler-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let link = format!("http://{}/sub", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let body = "http://127.0.0.1:9/scheduled-node#scheduled-node\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(7, ?1, ?2, '* * * * *', 1, '', '', 'scheduled')",
            params![iso8601_utc(unix_utc(2026, 6, 17, 0, 0, 0)), link],
        )
        .unwrap();
        drop(conn);

        let runtime = ProductRuntimeManager::new();
        let report = refresh_due_subscriptions_for_scheduler(
            &state,
            &dir,
            &runtime,
            unix_utc(2026, 6, 17, 0, 1, 0),
        )
        .unwrap();
        handle.join().unwrap();

        assert_eq!(report["dueCount"], json!(1));
        assert_eq!(report["refreshed"], json!(1));
        let conn = open_state_connection(&state).unwrap();
        let imported: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE subscription_id = 7 AND name = 'scheduled-node'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(imported, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scheduler_fetch_failure_is_not_counted_as_refresh_or_runtime_change() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-scheduler-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(7, ?1, 'file://missing-subscription.txt', '* * * * *', 1, '', '', 'scheduled')",
            params![iso8601_utc(unix_utc(2026, 6, 17, 0, 0, 0))],
        )
        .unwrap();
        drop(conn);

        let runtime = ProductRuntimeManager::new();
        let report = refresh_due_subscriptions_for_scheduler(
            &state,
            &dir,
            &runtime,
            unix_utc(2026, 6, 17, 0, 1, 0),
        )
        .unwrap();

        assert_eq!(report["attempted"], json!(1));
        assert_eq!(report["dueCount"], json!(1));
        assert_eq!(report["refreshed"], json!(0));
        assert_eq!(report["fetchErrors"], json!(1));
        assert_eq!(report["runtimeInputChanged"], json!(0));
        assert_eq!(report["runtimeReloaded"], json!(false));
        fs::remove_dir_all(dir).unwrap();
    }

    fn unix_utc(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> u64 {
        let year = year - i64::from(month <= 2);
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let yoe = year - era * 400;
        let month_prime = month + if month > 2 { -3 } else { 9 };
        let doy = (153 * month_prime + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        (days * 86_400 + hour * 3_600 + minute * 60 + second) as u64
    }
}
