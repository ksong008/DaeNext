use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use dae_product_core::product_civil_from_days;
use dae_product_core::product_iso8601_utc;
use dae_product_core::{product_now_text, unix_now};
use dae_product_persistence::{ensure_state_schema, open_state_connection, set_metadata};
use rusqlite::Connection;
use serde_json::{Value, json};

use crate::SubscriptionRefreshOutcome;

#[derive(Clone, Debug)]
pub struct ScheduledSubscription {
    pub id: i64,
    pub updated_at: String,
    pub cron_exp: String,
}

#[derive(Debug)]
pub struct ScheduledSubscriptionScan {
    pub due: Vec<ScheduledSubscription>,
    pub invalid_cron: Vec<InvalidScheduledSubscriptionCron>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidScheduledSubscriptionCron {
    pub id: i64,
    pub error: String,
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
pub fn validate_subscription_cron_expression(raw: &str) -> Result<(), String> {
    parse_cron_expression(raw).map(|_| ())
}

pub fn due_scheduled_subscriptions(
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
        .map_err(scheduler_sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ScheduledSubscription {
                id: row.get(0)?,
                updated_at: row.get(1)?,
                cron_exp: row.get(2)?,
            })
        })
        .map_err(scheduler_sqlite_io_error)?;
    let mut due = Vec::new();
    let mut invalid = Vec::new();
    for row in rows {
        let subscription = row.map_err(scheduler_sqlite_io_error)?;
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

pub fn next_scheduled_subscription_deadline(
    conn: &Connection,
    now_unix: u64,
) -> io::Result<Option<u64>> {
    let mut stmt = conn
        .prepare(
            "SELECT updated_at, COALESCE(cron_exp, '10 */6 * * *')
             FROM subscriptions
             WHERE cron_enable != 0",
        )
        .map_err(scheduler_sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(scheduler_sqlite_io_error)?;
    let mut next_deadline = None;
    for row in rows {
        let (updated_at, cron_exp) = row.map_err(scheduler_sqlite_io_error)?;
        let Ok(cron) = parse_cron_expression(&cron_exp) else {
            continue;
        };
        let Some(last_unix) = parse_iso8601_utc(&updated_at) else {
            next_deadline = min_deadline(next_deadline, now_unix.saturating_add(60));
            continue;
        };
        if last_unix < now_unix && next_cron_moment_after(&cron, last_unix, now_unix).is_some() {
            next_deadline = min_deadline(next_deadline, now_unix.saturating_add(60));
            continue;
        }
        let horizon = now_unix.saturating_add(4 * 366 * 24 * 60 * 60);
        if let Some(deadline) = next_cron_moment_after(&cron, now_unix, horizon) {
            next_deadline = min_deadline(next_deadline, deadline);
        }
    }
    Ok(next_deadline)
}

fn min_deadline(current: Option<u64>, candidate: u64) -> Option<u64> {
    Some(current.map_or(candidate, |current| current.min(candidate)))
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
    // Due iff the next cron moment after `last_unix` has already arrived,
    // which is exactly "some scheduled moment fell in (last_unix, now]".
    Ok(next_cron_moment_after(&cron, last_unix, now_unix).is_some())
}

/// Smallest cron moment strictly after `after_unix` that is still <=
/// `horizon_unix`, or None when no such moment exists.  The search walks the
/// cron fields (month/day/hour/minute) instead of probing every minute, so a
/// stale subscription whose `updated_at` sits a year in the past costs a
/// handful of calendar jumps rather than a ~527k-minute window scan per tick.
fn next_cron_moment_after(
    cron: &CronExpression,
    after_unix: u64,
    horizon_unix: u64,
) -> Option<u64> {
    let start = ((after_unix / 60) + 1) * 60;
    if start > horizon_unix {
        return None;
    }
    let (mut year, mut month, mut day, mut hour, mut minute) = decompose_unix(start);
    let horizon_year = decompose_unix(horizon_unix).0;
    loop {
        if year > horizon_year {
            return None;
        }
        if !cron.month.matches(month as u8) {
            advance_to_next_matching_month(&mut year, &mut month, &cron.month.values)?;
            day = 1;
            hour = 0;
            minute = i64::from(first_field_value(&cron.minute.values)?);
            continue;
        }
        if !cron_day_matches(cron, year, month, day) {
            if day < days_in_month(year, month) {
                day += 1;
            } else {
                advance_to_next_matching_month(&mut year, &mut month, &cron.month.values)?;
                day = 1;
            }
            hour = 0;
            minute = i64::from(first_field_value(&cron.minute.values)?);
            continue;
        }
        if !cron.hour.matches(hour as u8) {
            match next_field_value(&cron.hour.values, hour as u8) {
                Some(next) => hour = i64::from(next),
                None => {
                    if day < days_in_month(year, month) {
                        day += 1;
                    } else {
                        advance_to_next_matching_month(&mut year, &mut month, &cron.month.values)?;
                        day = 1;
                    }
                    hour = i64::from(first_field_value(&cron.hour.values)?);
                }
            }
            minute = i64::from(first_field_value(&cron.minute.values)?);
            continue;
        }
        if !cron.minute.matches(minute as u8) {
            match next_field_value(&cron.minute.values, minute as u8) {
                Some(next) => minute = i64::from(next),
                None => {
                    match next_field_value(&cron.hour.values, hour as u8) {
                        Some(next) => hour = i64::from(next),
                        None => {
                            if day < days_in_month(year, month) {
                                day += 1;
                            } else {
                                advance_to_next_matching_month(
                                    &mut year,
                                    &mut month,
                                    &cron.month.values,
                                )?;
                                day = 1;
                            }
                            hour = i64::from(first_field_value(&cron.hour.values)?);
                        }
                    }
                    minute = i64::from(first_field_value(&cron.minute.values)?);
                }
            }
            continue;
        }
        // Every field matches: this is the smallest matching moment at or
        // after the start position, and positions only move forward from
        // here, so a candidate beyond the horizon ends the search.
        let candidate = unix_from_components(year, month, day, hour, minute)?;
        return if candidate >= start && candidate <= horizon_unix {
            Some(candidate)
        } else {
            None
        };
    }
}

/// Advance to the next matching month, rolling into the following year when
/// the current year has no later matching month.  Returns None only for an
/// empty month field (defensive; parsing rejects it).
fn advance_to_next_matching_month(
    year: &mut i64,
    month: &mut i64,
    month_values: &BTreeSet<u8>,
) -> Option<()> {
    match next_field_value(month_values, *month as u8) {
        Some(next) => *month = i64::from(next),
        None => {
            *year += 1;
            *month = i64::from(first_field_value(month_values)?);
        }
    }
    Some(())
}

fn decompose_unix(unix: u64) -> (i64, i64, i64, i64, i64) {
    let seconds = unix as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = product_civil_from_days(days);
    (year, month, day, rem / 3_600, (rem % 3_600) / 60)
}

fn unix_from_components(year: i64, month: i64, day: i64, hour: i64, minute: i64) -> Option<u64> {
    let days = days_from_civil(year, month, day)?;
    Some((days as u64) * 86_400 + (hour * 3_600 + minute * 60) as u64)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn cron_day_matches(cron: &CronExpression, year: i64, month: i64, day: i64) -> bool {
    days_from_civil(year, month, day)
        .map(|days| {
            let day_of_week = (days + 4).rem_euclid(7) as u8;
            cron.matches_day(day as u8, day_of_week)
        })
        .unwrap_or(false)
}

fn first_field_value(values: &BTreeSet<u8>) -> Option<u8> {
    values.iter().next().copied()
}

fn next_field_value(values: &BTreeSet<u8>, current: u8) -> Option<u8> {
    values.iter().find(|value| **value > current).copied()
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

#[derive(Debug, Default)]
pub struct InvalidCronLogTracker {
    reported: HashMap<i64, String>,
}

impl InvalidCronLogTracker {
    pub fn take_changed(
        &mut self,
        current: &[InvalidScheduledSubscriptionCron],
    ) -> Vec<InvalidScheduledSubscriptionCron> {
        let active_ids = current.iter().map(|item| item.id).collect::<HashSet<_>>();
        self.reported.retain(|id, _| active_ids.contains(id));

        let mut changed = Vec::new();
        for invalid in current {
            if self.reported.get(&invalid.id) != Some(&invalid.error) {
                changed.push(invalid.clone());
            }
            self.reported.insert(invalid.id, invalid.error.clone());
        }
        changed
    }
}

#[derive(Debug, Default)]
pub struct SubscriptionSchedulerRuntimeApply {
    pub requested: bool,
    pub applied: bool,
    pub report: Value,
    pub error: Option<String>,
}

pub trait SubscriptionSchedulerCallbacks: Send + Sync {
    fn refresh_subscription(
        &self,
        state: &Path,
        config_dir: &Path,
        subscription_id: i64,
    ) -> io::Result<Value>;

    fn apply_runtime(
        &self,
        state: &Path,
        config_dir: &Path,
        requested: bool,
    ) -> SubscriptionSchedulerRuntimeApply;

    fn append_log(&self, config_dir: &Path, state: &Path, level: &str, message: &str);
}

#[derive(Debug)]
enum SchedulerCommand {
    Stop,
    Wake,
}

type SchedulerWakeRegistry = Mutex<Option<(u64, Sender<SchedulerCommand>)>>;

static NEXT_SCHEDULER_ID: AtomicU64 = AtomicU64::new(1);
static SCHEDULER_WAKE: OnceLock<SchedulerWakeRegistry> = OnceLock::new();

#[derive(Debug)]
pub struct SubscriptionSchedulerHandle {
    id: u64,
    stop: Option<Sender<SchedulerCommand>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SubscriptionSchedulerHandle {
    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(SchedulerCommand::Stop);
        }
        let Some(thread) = self.thread.take() else {
            unregister_scheduler(self.id);
            return Ok(());
        };
        let result = thread
            .join()
            .map_err(|_| io::Error::other("subscription scheduler thread panicked"));
        unregister_scheduler(self.id);
        result
    }
}

impl Drop for SubscriptionSchedulerHandle {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

pub fn start_subscription_scheduler<C: SubscriptionSchedulerCallbacks + 'static>(
    state: std::path::PathBuf,
    config_dir: std::path::PathBuf,
    callbacks: Arc<C>,
) -> io::Result<SubscriptionSchedulerHandle> {
    let (stop, receiver) = std::sync::mpsc::channel();
    let id = NEXT_SCHEDULER_ID.fetch_add(1, Ordering::Relaxed);
    register_scheduler(id, stop.clone())?;
    let thread = thread::Builder::new()
        .name("daed-subscription-scheduler".to_owned())
        .spawn(move || run_subscription_scheduler(state, config_dir, callbacks, receiver));
    let thread = match thread {
        Ok(thread) => thread,
        Err(error) => {
            unregister_scheduler(id);
            return Err(error);
        }
    };
    Ok(SubscriptionSchedulerHandle {
        id,
        stop: Some(stop),
        thread: Some(thread),
    })
}

pub fn notify_subscription_scheduler() {
    let Some(registry) = SCHEDULER_WAKE.get() else {
        return;
    };
    let Ok(registry) = registry.lock() else {
        return;
    };
    if let Some((_, sender)) = registry.as_ref() {
        let _ = sender.send(SchedulerCommand::Wake);
    }
}

fn register_scheduler(id: u64, sender: Sender<SchedulerCommand>) -> io::Result<()> {
    let registry = SCHEDULER_WAKE.get_or_init(|| Mutex::new(None));
    let mut registry = registry
        .lock()
        .map_err(|_| io::Error::other("subscription scheduler registry lock poisoned"))?;
    if registry.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "subscription scheduler is already running",
        ));
    }
    *registry = Some((id, sender));
    Ok(())
}

fn unregister_scheduler(id: u64) {
    let Some(registry) = SCHEDULER_WAKE.get() else {
        return;
    };
    let Ok(mut registry) = registry.lock() else {
        return;
    };
    if registry.as_ref().is_some_and(|(current, _)| *current == id) {
        *registry = None;
    }
}

fn run_subscription_scheduler<C: SubscriptionSchedulerCallbacks + 'static>(
    state: std::path::PathBuf,
    config_dir: std::path::PathBuf,
    callbacks: Arc<C>,
    stop: Receiver<SchedulerCommand>,
) {
    let _ = ensure_state_schema(&state);
    let _ = set_metadata(
        &state,
        "subscription_scheduler_started_at",
        &product_now_text(),
    );
    callbacks.append_log(
        &config_dir,
        &state,
        "info",
        "subscription scheduler started by Rust daed",
    );
    let mut invalid_cron = InvalidCronLogTracker::default();
    loop {
        let mut wake_during_refresh = false;
        let refresh = refresh_due_subscriptions_with_control(
            callbacks.as_ref(),
            &state,
            &config_dir,
            unix_now(),
            &mut invalid_cron,
            || loop {
                match stop.try_recv() {
                    Ok(SchedulerCommand::Wake) => wake_during_refresh = true,
                    Ok(SchedulerCommand::Stop)
                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => return true,
                    Err(std::sync::mpsc::TryRecvError::Empty) => return false,
                }
            },
        );
        match refresh {
            Ok(None) => break,
            Ok(Some(_)) => {}
            Err(error) => {
                callbacks.append_log(
                    &config_dir,
                    &state,
                    "error",
                    &format!("subscription scheduler tick failed: {error}"),
                );
            }
        }
        if wake_during_refresh {
            continue;
        }
        let wait = match subscription_scheduler_wait(&state, unix_now()) {
            Ok(Some(wait)) => Some(wait),
            Ok(None) => None,
            Err(_) => Some(Duration::from_secs(60)),
        };
        let command = match wait {
            Some(wait) => match stop.recv_timeout(wait) {
                Ok(command) => Some(command),
                Err(RecvTimeoutError::Disconnected) => Some(SchedulerCommand::Stop),
                Err(RecvTimeoutError::Timeout) => None,
            },
            None => match stop.recv() {
                Ok(command) => Some(command),
                Err(_) => Some(SchedulerCommand::Stop),
            },
        };
        match command {
            Some(SchedulerCommand::Stop) => break,
            Some(SchedulerCommand::Wake) => loop {
                match stop.try_recv() {
                    Ok(SchedulerCommand::Wake) => {}
                    Ok(SchedulerCommand::Stop)
                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            },
            None => {}
        }
    }
    let _ = set_metadata(
        &state,
        "subscription_scheduler_stopped_at",
        &product_now_text(),
    );
}

fn subscription_scheduler_wait(state: &Path, now_unix: u64) -> io::Result<Option<Duration>> {
    let conn = open_state_connection(state)?;
    let deadline = next_scheduled_subscription_deadline(&conn, now_unix)?;
    Ok(deadline.map(|deadline| Duration::from_secs(deadline.saturating_sub(now_unix).max(1))))
}

pub fn refresh_due_subscriptions_with_callbacks<C: SubscriptionSchedulerCallbacks>(
    callbacks: &C,
    state: &Path,
    config_dir: &Path,
    now_unix: u64,
    invalid_cron: &mut InvalidCronLogTracker,
) -> io::Result<Value> {
    refresh_due_subscriptions_with_control(
        callbacks,
        state,
        config_dir,
        now_unix,
        invalid_cron,
        || false,
    )?
    .ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "subscription refresh cancelled"))
}

fn refresh_due_subscriptions_with_control<C, F>(
    callbacks: &C,
    state: &Path,
    config_dir: &Path,
    now_unix: u64,
    invalid_cron: &mut InvalidCronLogTracker,
    mut stop_requested: F,
) -> io::Result<Option<Value>>
where
    C: SubscriptionSchedulerCallbacks,
    F: FnMut() -> bool,
{
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let scan = due_scheduled_subscriptions(&conn, now_unix)?;
    drop(conn);

    for invalid in invalid_cron.take_changed(&scan.invalid_cron) {
        callbacks.append_log(
            config_dir,
            state,
            "error",
            &format!(
                "subscription {} scheduler cron error: {}",
                invalid.id, invalid.error
            ),
        );
    }

    let attempted = scan.due.len();
    let mut fetched = 0_usize;
    let mut fetch_errors = 0_usize;
    let mut runtime_input_changes = 0_usize;
    for subscription in &scan.due {
        if stop_requested() {
            return Ok(None);
        }
        match callbacks.refresh_subscription(state, config_dir, subscription.id) {
            Ok(report) => {
                let outcome = SubscriptionRefreshOutcome::from_report(&report);
                if outcome.fetched {
                    fetched += 1;
                } else {
                    fetch_errors += 1;
                }
                if outcome.requests_runtime_apply() {
                    runtime_input_changes += 1;
                }
                callbacks.append_log(
                    config_dir,
                    state,
                    if outcome.fetched { "info" } else { "error" },
                    &format!(
                        "subscription {} {} by scheduler",
                        subscription.id,
                        if outcome.fetched {
                            "refreshed"
                        } else {
                            "refresh fetch failed"
                        }
                    ),
                );
            }
            Err(error) => {
                fetch_errors += 1;
                callbacks.append_log(
                    config_dir,
                    state,
                    "error",
                    &format!(
                        "subscription {} scheduler refresh failed: {error}",
                        subscription.id
                    ),
                );
            }
        }
    }

    if stop_requested() {
        return Ok(None);
    }
    let runtime_apply = callbacks.apply_runtime(state, config_dir, runtime_input_changes > 0);
    let checked_at = product_iso8601_utc(now_unix);
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
    Ok(Some(json!({
        "checkedAt": checked_at,
        "attempted": attempted,
        "dueCount": scan.due.len(),
        "refreshed": fetched,
        "runtimeInputChanged": runtime_input_changes,
        "fetchErrors": fetch_errors,
        "invalidCronCount": scan.invalid_cron.len(),
        "runtimeApplyRequested": runtime_apply.requested,
        "runtimeReloaded": runtime_apply.applied,
        "runtimeReload": runtime_apply.report,
        "runtimeReloadError": runtime_apply.error,
    })))
}

fn scheduler_sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicUsize;

    use dae_product_core::product_iso8601_utc;
    use dae_product_persistence::{ensure_state_schema, open_state_connection};
    use rusqlite::params;

    #[test]
    fn subscription_cron_due_since_matches_default_schedule() {
        let last = unix_utc(2026, 6, 17, 0, 11, 0);
        let due = unix_utc(2026, 6, 17, 6, 10, 0);
        let before_next = unix_utc(2026, 6, 17, 7, 0, 0);

        assert!(subscription_cron_due_since("10 */6 * * *", last, due).unwrap());
        assert!(!subscription_cron_due_since("10 */6 * * *", due, before_next).unwrap());
    }

    #[test]
    fn subscription_cron_due_since_handles_stale_subscriptions_without_window_scan() {
        // A subscription last updated over a year ago must still be reported
        // due when a cron moment fell between its last update and now (the
        // old minute-by-minute window scan cost ~527k probes per tick here).
        let stale_last = unix_utc(2024, 1, 1, 0, 0, 0);
        let now = unix_utc(2025, 6, 17, 10, 0, 0);
        assert!(subscription_cron_due_since("0 0 * * *", stale_last, now).unwrap());
        // Not due while the next cron moment is still in the future.
        let recent_last = unix_utc(2025, 6, 17, 0, 0, 0);
        assert!(!subscription_cron_due_since("0 0 * * *", recent_last, now).unwrap());
        // A cron that can never match (Feb 30) must terminate and report not
        // due instead of scanning forever.
        assert!(!subscription_cron_due_since("0 0 30 2 *", stale_last, now).unwrap());
    }

    #[test]
    fn next_cron_moment_after_finds_the_first_matching_moment() {
        let far_future = unix_utc(2040, 1, 1, 0, 0, 0);
        let cron = parse_cron_expression("10 */6 * * *").unwrap();
        assert_eq!(
            next_cron_moment_after(&cron, unix_utc(2026, 6, 17, 0, 11, 0), far_future).unwrap(),
            unix_utc(2026, 6, 17, 6, 10, 0)
        );
        // A Feb-29 schedule skips non-leap years.
        let feb29 = parse_cron_expression("0 0 29 2 *").unwrap();
        assert_eq!(
            next_cron_moment_after(&feb29, unix_utc(2026, 3, 1, 0, 0, 0), far_future).unwrap(),
            unix_utc(2028, 2, 29, 0, 0, 0)
        );
        // The horizon caps the search: the next moment exists but is later.
        assert_eq!(
            next_cron_moment_after(
                &cron,
                unix_utc(2026, 6, 17, 6, 10, 0),
                unix_utc(2026, 6, 17, 7, 0, 0)
            ),
            None
        );
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
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(2, ?1, 'http://127.0.0.1:9/b', '0 */2 * * *', 0, '', '', 'b')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(3, ?1, 'http://127.0.0.1:9/c', '0 */2 * * *', 1, '', '', 'c')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 2, 1, 0))],
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
    fn next_subscription_deadline_returns_nearest_enabled_schedule() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-scheduler-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(1, ?1, 'file://a', '0 */2 * * *', 1, '', '', 'a')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(2, ?1, 'file://b', '10 * * * *', 1, '', '', 'b')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(3, ?1, 'file://c', '0 * * * *', 0, '', '', 'c')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 1, 0))],
        )
        .unwrap();

        let now = unix_utc(2026, 6, 17, 0, 2, 0);
        assert_eq!(
            next_scheduled_subscription_deadline(&conn, now).unwrap(),
            Some(unix_utc(2026, 6, 17, 0, 10, 0))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn due_subscription_deadline_is_delayed_for_retry() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-scheduler-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
             VALUES(1, ?1, 'file://a', '0 * * * *', 1, '', '', 'a')",
            params![product_iso8601_utc(unix_utc(2026, 6, 17, 0, 0, 0))],
        )
        .unwrap();

        let now = unix_utc(2026, 6, 17, 1, 2, 0);
        assert_eq!(
            next_scheduled_subscription_deadline(&conn, now).unwrap(),
            Some(now + 60)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn unix_utc(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> u64 {
        let days = days_from_civil(year, month, day).unwrap();
        (days * 86_400 + hour * 3_600 + minute * 60 + second) as u64
    }

    #[test]
    fn unchanged_cron_errors_are_reported_once_until_recovery() {
        let mut tracker = InvalidCronLogTracker::default();
        let invalid = |error: &str| InvalidScheduledSubscriptionCron {
            id: 1,
            error: error.to_owned(),
        };
        assert_eq!(tracker.take_changed(&[invalid("first")]).len(), 1);
        assert!(tracker.take_changed(&[invalid("first")]).is_empty());
        assert_eq!(
            tracker.take_changed(&[invalid("second")]),
            vec![invalid("second")]
        );
        assert!(tracker.take_changed(&[]).is_empty());
        assert_eq!(tracker.take_changed(&[invalid("second")]).len(), 1);
    }

    struct SchedulerLifecycleCallbacks {
        log_calls: AtomicUsize,
    }

    impl SubscriptionSchedulerCallbacks for SchedulerLifecycleCallbacks {
        fn refresh_subscription(
            &self,
            _state: &Path,
            _config_dir: &Path,
            _subscription_id: i64,
        ) -> io::Result<Value> {
            Ok(json!({"fetched": false}))
        }

        fn apply_runtime(
            &self,
            _state: &Path,
            _config_dir: &Path,
            _requested: bool,
        ) -> SubscriptionSchedulerRuntimeApply {
            SubscriptionSchedulerRuntimeApply::default()
        }

        fn append_log(&self, _config_dir: &Path, _state: &Path, _level: &str, _message: &str) {
            self.log_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CancellationCallbacks {
        refresh_calls: AtomicUsize,
        apply_calls: AtomicUsize,
    }

    impl SubscriptionSchedulerCallbacks for CancellationCallbacks {
        fn refresh_subscription(
            &self,
            _state: &Path,
            _config_dir: &Path,
            _subscription_id: i64,
        ) -> io::Result<Value> {
            self.refresh_calls.fetch_add(1, Ordering::Relaxed);
            Ok(json!({"fetched": true}))
        }

        fn apply_runtime(
            &self,
            _state: &Path,
            _config_dir: &Path,
            _requested: bool,
        ) -> SubscriptionSchedulerRuntimeApply {
            self.apply_calls.fetch_add(1, Ordering::Relaxed);
            SubscriptionSchedulerRuntimeApply::default()
        }

        fn append_log(&self, _config_dir: &Path, _state: &Path, _level: &str, _message: &str) {}
    }

    #[test]
    fn due_batch_stop_check_bounds_shutdown_to_the_current_refresh() {
        let directory = std::env::temp_dir().join(format!(
            "dae-product-subscription-scheduler-cancel-{}",
            fastrand::u64(..)
        ));
        let state = directory.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        for id in [1_i64, 2] {
            conn.execute(
                "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
                 VALUES(?1, '2026-06-17T00:00:00Z', 'file://fixture', '* * * * *', 1, '', '', ?2)",
                params![id, format!("fixture-{id}")],
            )
            .unwrap();
        }
        drop(conn);
        let callbacks = CancellationCallbacks {
            refresh_calls: AtomicUsize::new(0),
            apply_calls: AtomicUsize::new(0),
        };
        let mut invalid_cron = InvalidCronLogTracker::default();

        let outcome = refresh_due_subscriptions_with_control(
            &callbacks,
            &state,
            &directory,
            unix_utc(2026, 6, 17, 0, 2, 0),
            &mut invalid_cron,
            || callbacks.refresh_calls.load(Ordering::Relaxed) >= 1,
        )
        .unwrap();

        assert!(outcome.is_none());
        assert_eq!(callbacks.refresh_calls.load(Ordering::Relaxed), 1);
        assert_eq!(callbacks.apply_calls.load(Ordering::Relaxed), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn scheduler_handle_owns_thread_and_releases_singleton_registration() {
        let directory = std::env::temp_dir().join(format!(
            "dae-product-subscription-scheduler-lifecycle-{}",
            fastrand::u64(..)
        ));
        let state = directory.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let callbacks = Arc::new(SchedulerLifecycleCallbacks {
            log_calls: AtomicUsize::new(0),
        });
        let handle =
            start_subscription_scheduler(state.clone(), directory.clone(), Arc::clone(&callbacks))
                .unwrap();
        let second =
            start_subscription_scheduler(state.clone(), directory.clone(), Arc::clone(&callbacks))
                .unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::AlreadyExists);
        handle.shutdown().unwrap();
        assert!(callbacks.log_calls.load(Ordering::Relaxed) >= 1);

        let replacement =
            start_subscription_scheduler(state, directory.clone(), callbacks).unwrap();
        replacement.shutdown().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
