use super::*;

const SUBSCRIPTION_SCHEDULER_TICK: Duration = Duration::from_secs(60);
const SUBSCRIPTION_SCHEDULER_LOOKBACK_LIMIT_SECS: u64 = 366 * 24 * 60 * 60;

#[derive(Clone, Debug)]
struct ScheduledSubscription {
    id: i64,
    updated_at: String,
    cron_exp: String,
}

#[derive(Debug)]
struct ScheduledSubscriptionScan {
    due: Vec<ScheduledSubscription>,
    invalid_cron: Vec<InvalidScheduledSubscriptionCron>,
}

#[derive(Debug)]
struct InvalidScheduledSubscriptionCron {
    id: i64,
    error: String,
}

#[derive(Clone, Debug)]
struct CronExpression {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
}

#[derive(Clone, Debug)]
struct CronField {
    wildcard: bool,
    values: BTreeSet<u8>,
}

#[derive(Clone, Copy, Debug)]
struct CronMoment {
    minute: u8,
    hour: u8,
    day_of_month: u8,
    month: u8,
    day_of_week: u8,
}

pub(crate) fn start_subscription_scheduler(
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
) {
    let _ = thread::Builder::new()
        .name("daed-subscription-scheduler".to_owned())
        .spawn(move || {
            let _ = ensure_state_schema(&state);
            let _ = set_metadata(&state, "subscription_scheduler_started_at", &now_text());
            let _ = append_log_for_config(
                &config_dir,
                &state,
                "info",
                "subscription scheduler started by Rust daed",
            );
            loop {
                if let Err(err) = refresh_due_subscriptions_for_scheduler(
                    &state,
                    &config_dir,
                    &runtime,
                    unix_now(),
                ) {
                    let _ = append_log_for_config(
                        &config_dir,
                        &state,
                        "error",
                        &format!("subscription scheduler tick failed: {err}"),
                    );
                }
                thread::sleep(SUBSCRIPTION_SCHEDULER_TICK);
            }
        });
}

pub(crate) fn refresh_due_subscriptions_for_scheduler(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    now_unix: u64,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let scan = due_scheduled_subscriptions(&conn, now_unix)?;
    drop(conn);

    for invalid in &scan.invalid_cron {
        let _ = append_log_for_config(
            config_dir,
            state,
            "error",
            &format!(
                "subscription {} scheduler cron error: {}",
                invalid.id, invalid.error
            ),
        );
    }

    let mut refreshed = 0_usize;
    let mut fetch_errors = 0_usize;
    for subscription in &scan.due {
        match refresh_subscription_from_remote(state, subscription.id) {
            Ok(report) => {
                refreshed += 1;
                if !report["fetched"].as_bool().unwrap_or(false) {
                    fetch_errors += 1;
                }
                let _ = append_log_for_config(
                    config_dir,
                    state,
                    "info",
                    &format!("subscription {} refreshed by scheduler", subscription.id),
                );
            }
            Err(err) => {
                fetch_errors += 1;
                let _ = append_log_for_config(
                    config_dir,
                    state,
                    "error",
                    &format!(
                        "subscription {} scheduler refresh failed: {err}",
                        subscription.id
                    ),
                );
            }
        }
    }

    let mut runtime_reloaded = false;
    let mut runtime_reload_error = None::<String>;
    if refreshed > 0 {
        match reload_runtime_after_subscription_refresh(state, config_dir, runtime) {
            Ok(Some(_)) => runtime_reloaded = true,
            Ok(None) => {}
            Err(err) => runtime_reload_error = Some(err),
        }
    }

    let checked_at = iso8601_utc(now_unix);
    let _ = set_metadata(state, "subscription_scheduler_last_tick_at", &checked_at);
    let _ = set_metadata(
        state,
        "subscription_scheduler_last_due_count",
        &scan.due.len().to_string(),
    );
    let _ = set_metadata(
        state,
        "subscription_scheduler_last_invalid_count",
        &scan.invalid_cron.len().to_string(),
    );
    Ok(json!({
        "checkedAt": checked_at,
        "dueCount": scan.due.len(),
        "refreshed": refreshed,
        "fetchErrors": fetch_errors,
        "invalidCronCount": scan.invalid_cron.len(),
        "runtimeReloaded": runtime_reloaded,
        "runtimeReloadError": runtime_reload_error,
    }))
}

pub(crate) fn validate_subscription_cron_expression(raw: &str) -> Result<(), String> {
    parse_cron_expression(raw).map(|_| ())
}

fn due_scheduled_subscriptions(
    conn: &Connection,
    now_unix: u64,
) -> io::Result<ScheduledSubscriptionScan> {
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, COALESCE(cron_exp, '10 */6 * * *')
             FROM subscriptions
             WHERE cron_enable != 0
             ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ScheduledSubscription {
                id: row.get(0)?,
                updated_at: row.get(1)?,
                cron_exp: row.get(2)?,
            })
        })
        .map_err(sqlite_io_error)?;
    let mut due = Vec::new();
    let mut invalid = Vec::new();
    for row in rows {
        let subscription = row.map_err(sqlite_io_error)?;
        match subscription_due_at(&subscription.cron_exp, &subscription.updated_at, now_unix) {
            Ok(true) => due.push(subscription),
            Ok(false) => {}
            Err(err) => invalid.push(InvalidScheduledSubscriptionCron {
                id: subscription.id,
                error: err,
            }),
        }
    }
    Ok(ScheduledSubscriptionScan {
        due,
        invalid_cron: invalid,
    })
}

fn subscription_due_at(cron_exp: &str, updated_at: &str, now_unix: u64) -> Result<bool, String> {
    let Some(last_unix) = parse_iso8601_utc(updated_at) else {
        return Ok(true);
    };
    subscription_cron_due_since(cron_exp, last_unix, now_unix)
}

fn subscription_cron_due_since(
    cron_exp: &str,
    last_unix: u64,
    now_unix: u64,
) -> Result<bool, String> {
    if now_unix <= last_unix {
        return Ok(false);
    }
    let cron = parse_cron_expression(cron_exp)?;
    let end = (now_unix / 60) * 60;
    let lower = last_unix.max(now_unix.saturating_sub(SUBSCRIPTION_SCHEDULER_LOOKBACK_LIMIT_SECS));
    let mut cursor = ((lower / 60) + 1) * 60;
    while cursor <= end {
        if cron.matches_unix(cursor) {
            return Ok(true);
        }
        cursor = cursor.saturating_add(60);
    }
    Ok(false)
}

fn parse_cron_expression(raw: &str) -> Result<CronExpression, String> {
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err(format!(
            "subscription cron expression must have 5 fields; got {}",
            fields.len()
        ));
    }
    Ok(CronExpression {
        minute: parse_cron_field(fields[0], 0, 59, false, "minute")?,
        hour: parse_cron_field(fields[1], 0, 23, false, "hour")?,
        day_of_month: parse_cron_field(fields[2], 1, 31, false, "day-of-month")?,
        month: parse_cron_field(fields[3], 1, 12, false, "month")?,
        day_of_week: parse_cron_field(fields[4], 0, 7, true, "day-of-week")?,
    })
}

fn parse_cron_field(
    raw: &str,
    min: u8,
    max: u8,
    sunday_alias: bool,
    label: &str,
) -> Result<CronField, String> {
    if raw.trim().is_empty() {
        return Err(format!("subscription cron {label} field is empty"));
    }
    let wildcard = raw == "*";
    let mut values = BTreeSet::new();
    for part in raw.split(',') {
        add_cron_part_values(&mut values, part.trim(), min, max, sunday_alias, label)?;
    }
    if values.is_empty() {
        return Err(format!("subscription cron {label} field has no values"));
    }
    Ok(CronField { wildcard, values })
}

fn add_cron_part_values(
    values: &mut BTreeSet<u8>,
    raw: &str,
    min: u8,
    max: u8,
    sunday_alias: bool,
    label: &str,
) -> Result<(), String> {
    let (base, step) = match raw.split_once('/') {
        Some((base, step)) => {
            let step = step
                .parse::<usize>()
                .map_err(|err| format!("subscription cron {label} step is invalid: {err}"))?;
            if step == 0 {
                return Err(format!(
                    "subscription cron {label} step must be greater than 0"
                ));
            }
            (base, step)
        }
        None => (raw, 1),
    };
    let raw_values = if base == "*" {
        (min..=max).collect::<Vec<_>>()
    } else if let Some((from, to)) = base.split_once('-') {
        let from = parse_cron_u8(from, label)?;
        let to = parse_cron_u8(to, label)?;
        if from > to {
            return Err(format!(
                "subscription cron {label} range start must be <= end"
            ));
        }
        (from..=to).collect::<Vec<_>>()
    } else {
        vec![parse_cron_u8(base, label)?]
    };
    for (index, raw_value) in raw_values.into_iter().enumerate() {
        if index % step != 0 {
            continue;
        }
        values.insert(normalize_cron_value(
            raw_value,
            min,
            max,
            sunday_alias,
            label,
        )?);
    }
    Ok(())
}

fn parse_cron_u8(raw: &str, label: &str) -> Result<u8, String> {
    raw.parse::<u8>()
        .map_err(|err| format!("subscription cron {label} value is invalid: {err}"))
}

fn normalize_cron_value(
    value: u8,
    min: u8,
    max: u8,
    sunday_alias: bool,
    label: &str,
) -> Result<u8, String> {
    if sunday_alias && value == 7 {
        return Ok(0);
    }
    if value < min || value > max || (sunday_alias && value > 6) {
        return Err(format!(
            "subscription cron {label} value {value} is outside {min}..={max}"
        ));
    }
    Ok(value)
}

impl CronExpression {
    fn matches_unix(&self, unix: u64) -> bool {
        let moment = cron_moment_from_unix(unix);
        self.minute.matches(moment.minute)
            && self.hour.matches(moment.hour)
            && self.month.matches(moment.month)
            && self.matches_day(moment.day_of_month, moment.day_of_week)
    }

    fn matches_day(&self, day_of_month: u8, day_of_week: u8) -> bool {
        if !self.day_of_month.wildcard && !self.day_of_week.wildcard {
            return self.day_of_month.matches(day_of_month)
                || self.day_of_week.matches(day_of_week);
        }
        self.day_of_month.matches(day_of_month) && self.day_of_week.matches(day_of_week)
    }
}

impl CronField {
    fn matches(&self, value: u8) -> bool {
        self.values.contains(&value)
    }
}

fn cron_moment_from_unix(unix: u64) -> CronMoment {
    let seconds = unix as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (_year, month, day) = civil_from_days(days);
    CronMoment {
        minute: ((rem % 3_600) / 60) as u8,
        hour: (rem / 3_600) as u8,
        day_of_month: day as u8,
        month: month as u8,
        day_of_week: (days + 4).rem_euclid(7) as u8,
    }
}

fn parse_iso8601_utc(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.len() != 20 || !raw.ends_with('Z') {
        return None;
    }
    let year = raw.get(0..4)?.parse::<i64>().ok()?;
    let month = raw.get(5..7)?.parse::<i64>().ok()?;
    let day = raw.get(8..10)?.parse::<i64>().ok()?;
    let hour = raw.get(11..13)?.parse::<i64>().ok()?;
    let minute = raw.get(14..16)?.parse::<i64>().ok()?;
    let second = raw.get(17..19)?.parse::<i64>().ok()?;
    if raw.as_bytes().get(4) != Some(&b'-')
        || raw.as_bytes().get(7) != Some(&b'-')
        || raw.as_bytes().get(10) != Some(&b'T')
        || raw.as_bytes().get(13) != Some(&b':')
        || raw.as_bytes().get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some((days * 86_400 + hour * 3_600 + minute * 60 + second) as u64)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_cron_due_since_matches_default_schedule() {
        let last = unix_utc(2026, 6, 17, 0, 11, 0);
        let due = unix_utc(2026, 6, 17, 6, 10, 0);
        let before_next = unix_utc(2026, 6, 17, 7, 0, 0);

        assert!(subscription_cron_due_since("10 */6 * * *", last, due).unwrap());
        assert!(!subscription_cron_due_since("10 */6 * * *", due, before_next).unwrap());
    }

    #[test]
    fn subscription_cron_parser_supports_ranges_steps_and_sunday_alias() {
        assert!(parse_cron_expression("0,30 1-6/2 * * 0,7").is_ok());
        assert!(parse_cron_expression("*/15 * * * *").is_ok());
        assert!(parse_cron_expression("60 * * * *").is_err());
        assert!(parse_cron_expression("* * *").is_err());
    }

    #[test]
    fn scheduled_subscription_due_scan_respects_enable_and_updated_at() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-scheduler-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(1, ?1, 'http://127.0.0.1:9/a', '0 */2 * * *', 1, '', '', 'a')",
            params![iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(2, ?1, 'http://127.0.0.1:9/b', '0 */2 * * *', 0, '', '', 'b')",
            params![iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(3, ?1, 'http://127.0.0.1:9/c', '0 */2 * * *', 1, '', '', 'c')",
            params![iso8601_utc(unix_utc(2026, 6, 17, 2, 1, 0))],
        )
        .unwrap();

        let scan = due_scheduled_subscriptions(&conn, unix_utc(2026, 6, 17, 2, 0, 0)).unwrap();
        assert!(scan.invalid_cron.is_empty());
        assert_eq!(
            scan.due.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![1]
        );
        fs::remove_dir_all(dir).unwrap();
    }

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

    fn unix_utc(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> u64 {
        let days = days_from_civil(year, month, day).unwrap();
        (days * 86_400 + hour * 3_600 + minute * 60 + second) as u64
    }
}
