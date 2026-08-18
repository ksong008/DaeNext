use std::sync::{Arc, Condvar, Mutex};

use crate::error::DnsError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Upstream {
    pub scheme: String,
    pub hostname: String,
    pub port: u16,
    pub path: String,
    pub ip4: Option<String>,
    pub ip6: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UpstreamResolverStats {
    pub refresh_success_total: u64,
    pub refresh_failure_total: u64,
    pub stale_reuse_total: u64,
}

struct ResolverState {
    upstream: Option<Arc<Upstream>>,
    init: bool,
    refreshing: bool,
    next_refresh_unix: i64,
    stats: UpstreamResolverStats,
}

type ResolveFn = dyn FnMut() -> Result<Upstream, DnsError> + Send;
type FinishFn = dyn FnMut(&Upstream) -> Result<(), DnsError> + Send;

pub struct UpstreamResolver {
    state: Mutex<ResolverState>,
    cond: Condvar,
    refresh_interval_secs: i64,
    retry_interval_secs: i64,
    resolve: Mutex<Box<ResolveFn>>,
    finish: Mutex<Option<Box<FinishFn>>>,
}

impl UpstreamResolver {
    pub fn new(resolve: impl FnMut() -> Result<Upstream, DnsError> + Send + 'static) -> Self {
        Self {
            state: Mutex::new(ResolverState {
                upstream: None,
                init: false,
                refreshing: false,
                next_refresh_unix: 0,
                stats: UpstreamResolverStats::default(),
            }),
            cond: Condvar::new(),
            refresh_interval_secs: 600,
            retry_interval_secs: 60,
            resolve: Mutex::new(Box::new(resolve)),
            finish: Mutex::new(None),
        }
    }

    pub fn with_intervals(mut self, refresh_interval_secs: i64, retry_interval_secs: i64) -> Self {
        self.refresh_interval_secs = refresh_interval_secs;
        self.retry_interval_secs = retry_interval_secs;
        self
    }

    pub fn with_finish(
        self,
        finish: impl FnMut(&Upstream) -> Result<(), DnsError> + Send + 'static,
    ) -> Self {
        *self.finish.lock().unwrap() = Some(Box::new(finish));
        self
    }

    pub fn get_upstream(&self, now_unix: i64) -> Result<Arc<Upstream>, DnsError> {
        let old_upstream = loop {
            let mut state = self.state.lock().unwrap();
            if state.init && now_unix < state.next_refresh_unix {
                return Ok(state.upstream.as_ref().unwrap().clone());
            }
            if state.refreshing {
                drop(self.cond.wait(state).unwrap());
                continue;
            }
            state.refreshing = true;
            break state.upstream.clone();
        };

        // F-22: 用户提供的 resolve/finish 回调可能 panic——panic 会留下
        // refreshing=true 且不 notify，导致所有等待者永久冻结。用
        // catch_unwind 隔离并走统一失败路径（复位 + notify）。
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut resolve = self.resolve.lock().unwrap();
            resolve()
        }))
        .unwrap_or_else(|_| {
            Err(DnsError::Resolve(
                "dns upstream resolve callback panicked".to_owned(),
            ))
        });

        let result = match resolved {
            Ok(upstream) => {
                let finish_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut finish = self.finish.lock().unwrap();
                    match finish.as_mut() {
                        Some(finish) => finish(&upstream),
                        None => Ok(()),
                    }
                }))
                .unwrap_or_else(|_| {
                    Err(DnsError::Resolve(
                        "dns upstream finish callback panicked".to_owned(),
                    ))
                });
                finish_result.map(|_| Arc::new(upstream))
            }
            Err(err) => Err(err),
        };

        let mut state = self.state.lock().unwrap();
        state.refreshing = false;
        match result {
            Ok(new_upstream) => {
                state.stats.refresh_success_total += 1;
                state.upstream = Some(new_upstream.clone());
                state.init = true;
                state.next_refresh_unix = now_unix + self.refresh_interval_secs;
                self.cond.notify_all();
                Ok(new_upstream)
            }
            Err(err) => {
                state.stats.refresh_failure_total += 1;
                if let Some(old) = old_upstream {
                    state.stats.stale_reuse_total += 1;
                    state.next_refresh_unix = now_unix + self.retry_interval_secs;
                    self.cond.notify_all();
                    Ok(old)
                } else {
                    // F-23: 首次失败也写 retry 截止，避免 N 个并发请求
                    // 全部串行重试同一慢解析。
                    state.next_refresh_unix = now_unix + self.retry_interval_secs;
                    self.cond.notify_all();
                    Err(DnsError::Resolve(format!(
                        "failed to init dns upstream: {err}"
                    )))
                }
            }
        }
    }

    pub fn stats(&self) -> UpstreamResolverStats {
        self.state.lock().unwrap().stats
    }

    pub fn next_refresh_unix(&self) -> i64 {
        self.state.lock().unwrap().next_refresh_unix
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn upstream_resolver_refresh_matches_golden_fixture() {
        let fixture = dae_golden::load_json("dns/upstream/resolver_refresh.json").unwrap();
        let base_now = fixture["cache_before_refresh"]["now"].as_i64().unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = UpstreamResolver::new({
            let calls = Arc::clone(&calls);
            move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(upstream(if n == 0 { "1.1.1.1" } else { "1.1.1.2" }))
            }
        });
        let first = resolver.get_upstream(base_now).unwrap();
        let cached = resolver.get_upstream(base_now + 1).unwrap();
        assert!(Arc::ptr_eq(&first, &cached));
        assert_eq!(
            resolver.next_refresh_unix(),
            fixture["cache_before_refresh"]["refresh_after"]
                .as_i64()
                .unwrap()
        );
        assert_eq!(
            calls.load(Ordering::SeqCst) as u64,
            fixture["cache_before_refresh"]["resolve_calls"]
                .as_u64()
                .unwrap()
        );

        let refreshed = resolver.get_upstream(base_now + 700).unwrap();
        assert!(!Arc::ptr_eq(&first, &refreshed));
        assert_eq!(
            refreshed.ip4.as_deref(),
            fixture["refresh_after_interval"]["second_ip"].as_str()
        );
        assert_eq!(
            calls.load(Ordering::SeqCst) as u64,
            fixture["refresh_after_interval"]["resolve_calls"]
                .as_u64()
                .unwrap()
        );

        let stale_calls = Arc::new(AtomicUsize::new(0));
        let stale_resolver = UpstreamResolver::new({
            let stale_calls = Arc::clone(&stale_calls);
            move || {
                let n = stale_calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Ok(upstream("1.1.1.1"))
                } else {
                    Err(DnsError::Resolve("boom".to_owned()))
                }
            }
        })
        .with_intervals(120, 30);
        let first = stale_resolver.get_upstream(base_now).unwrap();
        let stale = stale_resolver.get_upstream(base_now + 120).unwrap();
        assert!(Arc::ptr_eq(&first, &stale));
        assert_eq!(
            stale_resolver.next_refresh_unix(),
            fixture["stale_on_failure"]["retry_deadline"]
                .as_i64()
                .unwrap()
        );
        let stats = stale_resolver.stats();
        assert_eq!(
            stats.refresh_success_total,
            fixture["stale_on_failure"]["refresh_success_delta"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            stats.refresh_failure_total,
            fixture["stale_on_failure"]["refresh_failure_delta"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            stats.stale_reuse_total,
            fixture["stale_on_failure"]["stale_reuse_delta"]
                .as_u64()
                .unwrap()
        );
    }

    #[test]
    fn upstream_resolver_deduplicates_concurrent_refresh() {
        let fixture = dae_golden::load_json("dns/upstream/resolver_refresh.json").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));
        let resolver = Arc::new(UpstreamResolver::new({
            let calls = Arc::clone(&calls);
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(25));
                Ok(upstream("1.1.1.1"))
            }
        }));

        let mut handles = Vec::new();
        for _ in 0..fixture["dedupe_concurrent_refresh"]["callers"]
            .as_u64()
            .unwrap()
        {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                resolver.get_upstream(100).unwrap()
            }));
        }

        let first = handles.remove(0).join().unwrap();
        let second = handles.remove(0).join().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            calls.load(Ordering::SeqCst) as u64,
            fixture["dedupe_concurrent_refresh"]["resolve_calls"]
                .as_u64()
                .unwrap()
        );
    }

    fn upstream(ip: &str) -> Upstream {
        Upstream {
            scheme: "udp".to_owned(),
            hostname: "dns.example.com".to_owned(),
            port: 53,
            path: String::new(),
            ip4: Some(ip.to_owned()),
            ip6: None,
        }
    }
}
