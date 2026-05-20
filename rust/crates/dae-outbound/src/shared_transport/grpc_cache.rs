use super::{GrpcLifecycleCache, GrpcLifecycleOptions};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcCacheCancellationStressReport {
    pub iterations: usize,
    pub same_key_reused: bool,
    pub server_name_splits_key: bool,
    pub allow_insecure_splits_key: bool,
    pub mark_splits_key: bool,
    pub mptcp_splits_key: bool,
    pub cleanup_closed_live_entries: bool,
    pub cleanup_zeroed_live_entries: bool,
    pub refill_after_cleanup_not_reused: bool,
    pub clean_hook_idempotent: bool,
    pub max_live_entries: usize,
    pub cleaned_entries_total: usize,
    pub closed_entries_total: usize,
    pub sample_cache_keys: Vec<String>,
    pub detached_stream_cancellation: GrpcDetachedStreamCancellationReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcDetachedStreamCancellationReport {
    pub parent_cancel_propagates_before_stop_following: bool,
    pub parent_cancel_ignored_after_stop_following: bool,
    pub stream_close_cancels: bool,
    pub stream_close_idempotent: bool,
}

pub fn grpc_cache_cleanup_cancellation_stress(
    base: &GrpcLifecycleOptions,
    iterations: usize,
) -> GrpcCacheCancellationStressReport {
    let iterations = iterations.max(1);
    let server_variant = GrpcLifecycleOptions::new(
        &base.address,
        &base.service_name,
        format!("{}-alt", base.server_name),
        &base.dialer_id,
        base.allow_insecure,
        base.mark,
        base.mptcp,
    );
    let insecure_variant = GrpcLifecycleOptions::new(
        &base.address,
        &base.service_name,
        &base.server_name,
        &base.dialer_id,
        !base.allow_insecure,
        base.mark,
        base.mptcp,
    );
    let mark_variant = GrpcLifecycleOptions::new(
        &base.address,
        &base.service_name,
        &base.server_name,
        &base.dialer_id,
        base.allow_insecure,
        base.mark.wrapping_add(1),
        base.mptcp,
    );
    let mptcp_variant = GrpcLifecycleOptions::new(
        &base.address,
        &base.service_name,
        &base.server_name,
        &base.dialer_id,
        base.allow_insecure,
        base.mark,
        !base.mptcp,
    );
    let base_key = base.cache_key();
    let server_key = server_variant.cache_key();
    let insecure_key = insecure_variant.cache_key();
    let mark_key = mark_variant.cache_key();
    let mptcp_key = mptcp_variant.cache_key();
    let mut cache = GrpcLifecycleCache::default();
    let mut same_key_reused = true;
    let mut cleanup_closed_live_entries = true;
    let mut cleanup_zeroed_live_entries = true;
    let mut refill_after_cleanup_not_reused = true;
    let mut clean_hook_idempotent = true;
    let mut max_live_entries = 0;
    let mut cleaned_entries_total = 0;

    for _ in 0..iterations {
        let first = cache.get_or_insert(base);
        let second = cache.get_or_insert(base);
        same_key_reused &= !first.reused
            && second.reused
            && first.key == second.key
            && second.use_count == 2
            && second.live_entries == 1;

        for options in [
            &server_variant,
            &insecure_variant,
            &mark_variant,
            &mptcp_variant,
        ] {
            cache.get_or_insert(options);
        }
        max_live_entries = max_live_entries.max(cache.live_entries());
        let live_before_clean = cache.live_entries();
        let cleaned = cache.clean();
        cleanup_closed_live_entries &= cleaned == live_before_clean;
        cleanup_zeroed_live_entries &= cache.live_entries() == 0;
        cleaned_entries_total += cleaned;

        let refill = cache.get_or_insert(base);
        refill_after_cleanup_not_reused &= !refill.reused && refill.live_entries == 1;
        let cleaned_refill = cache.clean();
        clean_hook_idempotent &=
            cleaned_refill == 1 && cache.clean() == 0 && cache.live_entries() == 0;
        cleaned_entries_total += cleaned_refill;
    }

    GrpcCacheCancellationStressReport {
        iterations,
        same_key_reused,
        server_name_splits_key: base_key != server_key,
        allow_insecure_splits_key: base_key != insecure_key,
        mark_splits_key: base_key != mark_key,
        mptcp_splits_key: base_key != mptcp_key,
        cleanup_closed_live_entries,
        cleanup_zeroed_live_entries,
        refill_after_cleanup_not_reused,
        clean_hook_idempotent,
        max_live_entries,
        cleaned_entries_total,
        closed_entries_total: cache.closed_entries(),
        sample_cache_keys: vec![base_key, server_key, insecure_key, mark_key, mptcp_key],
        detached_stream_cancellation: detached_stream_cancellation_stress(iterations),
    }
}

fn detached_stream_cancellation_stress(iterations: usize) -> GrpcDetachedStreamCancellationReport {
    let mut parent_cancel_propagates_before_stop_following = true;
    let mut parent_cancel_ignored_after_stop_following = true;
    let mut stream_close_cancels = true;
    let mut stream_close_idempotent = true;

    for _ in 0..iterations {
        let mut before_stop = DetachedStreamContextModel::new();
        before_stop.cancel_parent();
        parent_cancel_propagates_before_stop_following &= before_stop.stream_cancelled;

        let mut after_stop = DetachedStreamContextModel::new();
        after_stop.stop_following();
        after_stop.cancel_parent();
        parent_cancel_ignored_after_stop_following &= !after_stop.stream_cancelled;
        after_stop.close_stream();
        stream_close_cancels &= after_stop.stream_cancelled;
        let close_count = after_stop.close_count;
        after_stop.close_stream();
        stream_close_idempotent &=
            after_stop.stream_cancelled && after_stop.close_count == close_count;
    }

    GrpcDetachedStreamCancellationReport {
        parent_cancel_propagates_before_stop_following,
        parent_cancel_ignored_after_stop_following,
        stream_close_cancels,
        stream_close_idempotent,
    }
}

#[derive(Debug)]
struct DetachedStreamContextModel {
    following_parent: bool,
    stream_cancelled: bool,
    close_count: usize,
}

impl DetachedStreamContextModel {
    fn new() -> Self {
        Self {
            following_parent: true,
            stream_cancelled: false,
            close_count: 0,
        }
    }

    fn stop_following(&mut self) {
        self.following_parent = false;
    }

    fn cancel_parent(&mut self) {
        if self.following_parent {
            self.stream_cancelled = true;
        }
    }

    fn close_stream(&mut self) {
        if !self.stream_cancelled {
            self.stream_cancelled = true;
            self.close_count += 1;
        }
    }
}
