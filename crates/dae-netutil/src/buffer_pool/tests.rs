use super::*;

#[test]
fn lazy_growth_and_initialized_reuse() {
    let mut buffer = PooledBuffer::default();
    assert_eq!(buffer.capacity(), 0);
    buffer.resize(1200, 0x5a);
    buffer.resize(18000, 0x9b);
    assert_eq!(&buffer[..1200], &[0x5a; 1200]);
    assert!(buffer[1200..].iter().all(|&v| v == 0x9b));
    drop(buffer);
    let mut next = PooledBuffer::with_capacity(18000);
    assert!(next.is_empty());
    next.resize(18000, 0);
    assert!(next.iter().all(|&v| v == 0));
}

/// The global pool is shared by every test in this binary, and both acquisition
/// and return give up immediately when the lock is held. Callers can therefore
/// only rely on the invariants below, not on a given acquisition hitting.
#[test]
fn global_pool_respects_capacity_and_retention_bounds() {
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let buffers: Vec<_> = (0..64)
                    .map(|_| PooledBuffer::with_capacity(65536))
                    .collect();
                drop(buffers);
                drop(PooledBuffer::with_capacity(200000));
            });
        }
    });
    let pool = POOL.get().unwrap().lock().unwrap();
    assert!(pool.bytes <= IDLE_BUDGET);
    assert_eq!(
        pool.bytes,
        pool.bins.iter().flatten().map(Vec::capacity).sum::<usize>()
    );
    for (class, bin) in pool.bins.iter().enumerate() {
        assert!(bin.len() <= PER_CLASS_LIMIT);
        // A bin may hold storage wider than its class; never narrower, and
        // never above the retention ceiling.
        assert!(bin.iter().all(|buffer| buffer.capacity() >= CLASSES[class]
            && buffer.capacity() <= MAX_RETAINED_CAPACITY
            && buffer.is_empty()));
    }
}

/// Every acquisition must hand out at least the requested capacity, whichever
/// path it takes. This holds regardless of lock contention.
#[test]
fn acquisitions_never_undersize() {
    for &requested in &CLASSES {
        let buffer = PooledBuffer::with_capacity(requested);
        assert!(
            buffer.capacity() >= requested,
            "requested {requested}, got {}",
            buffer.capacity()
        );
    }
    for requested in [
        0,
        1,
        CLASSES[0] - 1,
        CLASSES[2] + 1,
        MAX_RETAINED_CAPACITY + 1,
    ] {
        let buffer = PooledBuffer::with_capacity(requested);
        assert!(
            buffer.capacity() >= requested,
            "requested {requested}, got {}",
            buffer.capacity()
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic tests over an isolated `Pool`.
//
// These drive `take_unlocked` / `return_unlocked` directly, so no other test can
// hold the lock, and every counter change is attributable.
// ---------------------------------------------------------------------------

/// Regression: `Vec` growth can push capacity off a class boundary. Such a
/// buffer must still be reused, and it must never be filed under a class wider
/// than its capacity, or `with_capacity` would hand out undersized storage.
#[test]
fn drifted_capacity_is_filed_under_a_satisfiable_class() {
    let drifted_capacity = CLASSES[1] + CLASSES[0] + 17;
    assert!(!CLASSES.contains(&drifted_capacity));
    assert!(drifted_capacity <= MAX_RETAINED_CAPACITY);

    let mut pool = Pool::default();
    return_unlocked(&mut pool, Vec::with_capacity(drifted_capacity));

    assert_eq!(pool.returns, 1);
    assert_eq!(pool.accepted_returns(), 1, "drift must still be retained");
    let (class, bin) = pool
        .bins
        .iter()
        .enumerate()
        .find(|(_, bin)| !bin.is_empty())
        .expect("drifted capacity should be retained");
    assert_eq!(bin.len(), 1);
    assert_eq!(bin[0].capacity(), drifted_capacity);
    assert!(
        CLASSES[class] <= drifted_capacity,
        "class {} ({}) must not exceed retained capacity {}",
        class,
        CLASSES[class],
        drifted_capacity
    );

    // The retained storage serves the request it is filed under, and any wider
    // request still allocates enough.
    let served = take_unlocked(&mut pool, class).expect("retained buffer should be taken");
    assert!(drifted_capacity >= CLASSES[class]);
    assert_eq!(served.capacity(), drifted_capacity);
}

#[test]
fn storage_above_the_retention_ceiling_is_rejected() {
    let mut pool = Pool::default();
    return_unlocked(&mut pool, Vec::with_capacity(MAX_RETAINED_CAPACITY + 1));

    assert_eq!(pool.returns, 1);
    assert_eq!(pool.rejected_oversized, 1);
    assert_eq!(pool.accepted_returns(), 0);
    assert!(
        pool.bins.iter().all(Vec::is_empty),
        "nothing may be retained"
    );
    assert_eq!(pool.bytes, 0);
}

#[test]
fn storage_below_the_smallest_class_is_rejected() {
    let mut pool = Pool::default();
    return_unlocked(&mut pool, Vec::with_capacity(CLASSES[0] - 1));

    assert_eq!(pool.returns, 1);
    assert_eq!(pool.rejected_unclassed, 1);
    assert!(pool.bins.iter().all(Vec::is_empty));
}

#[test]
fn budget_rejection_is_reported_separately_from_class_full() {
    // Class full: the smallest class fills without touching the byte budget.
    let mut pool = Pool::default();
    for _ in 0..PER_CLASS_LIMIT {
        return_unlocked(&mut pool, Vec::with_capacity(CLASSES[0]));
    }
    assert_eq!(pool.rejected_class_full, 0, "first {PER_CLASS_LIMIT} fit");
    assert_eq!(pool.bins[0].len(), PER_CLASS_LIMIT);
    assert_eq!(pool.bytes, PER_CLASS_LIMIT * CLASSES[0]);

    return_unlocked(&mut pool, Vec::with_capacity(CLASSES[0]));
    assert_eq!(pool.rejected_class_full, 1);
    assert_eq!(pool.rejected_budget, 0, "the budget was never the obstacle");

    // Budget: a class whose capacity no longer fits is rejected by the budget.
    let mut budget_pool = Pool::default();
    for _ in 0..PER_CLASS_LIMIT {
        return_unlocked(&mut budget_pool, Vec::with_capacity(MAX_RETAINED_CAPACITY));
    }
    assert_eq!(budget_pool.bytes, IDLE_BUDGET);
    assert_eq!(
        budget_pool.bytes,
        budget_pool.bins.iter().flatten().map(Vec::capacity).sum::<usize>()
    );
    return_unlocked(&mut budget_pool, Vec::with_capacity(CLASSES[0]));
    assert_eq!(budget_pool.rejected_budget, 1);
    assert_eq!(budget_pool.rejected_class_full, 0);
    let buffer = take_unlocked(&mut budget_pool, CLASSES.len() - 1).unwrap();
    assert_eq!(budget_pool.bytes, IDLE_BUDGET - buffer.capacity());
    return_unlocked(&mut budget_pool, buffer);
    assert_eq!(budget_pool.bytes, IDLE_BUDGET);
}

#[test]
fn counters_are_attributed_to_the_returning_operation() {
    let mut pool = Pool::default();

    return_unlocked(&mut pool, Vec::with_capacity(CLASSES[2]));
    assert_eq!(pool.returns, 1);
    assert_eq!(pool.accepted_returns(), 1);

    let taken = take_unlocked(&mut pool, 2).expect("returned buffer should be reusable");
    assert_eq!(taken.capacity(), CLASSES[2]);
    assert_eq!(pool.acquisitions, 1);
    assert_eq!(pool.hits, 1);
    assert_eq!(pool.bytes, 0, "taking must release retained budget");

    // A missing bin still counts as an acquisition, and as a miss.
    assert!(take_unlocked(&mut pool, 2).is_none());
    assert_eq!(pool.acquisitions, 2);
    assert_eq!(pool.hits, 1);

    // Every considered return is classified exactly once.
    assert_eq!(
        pool.accepted_returns()
            + pool.rejected_unclassed
            + pool.rejected_oversized
            + pool.rejected_budget
            + pool.rejected_class_full,
        pool.returns
    );
}

#[test]
fn stats_snapshot_reports_derived_totals() {
    let stats = pool_stats();
    assert_eq!(
        stats.misses,
        stats.acquisitions.saturating_sub(stats.hits),
        "misses are derived from acquisitions and hits"
    );
    assert_eq!(
        stats.accepted_returns
            + stats.rejected_unclassed
            + stats.rejected_oversized
            + stats.rejected_budget
            + stats.rejected_class_full,
        stats.returns,
        "every considered return must be classified exactly once"
    );
    assert!(stats.idle_bytes <= IDLE_BUDGET);
}

#[test]
fn retention_boundaries_clear_length_and_preserve_capacity() {
    for capacity in [
        MAX_RETAINED_CAPACITY - 1,
        MAX_RETAINED_CAPACITY,
        MAX_RETAINED_CAPACITY + 1,
        200_000,
    ] {
        let mut pool = Pool::default();
        let mut buffer = Vec::with_capacity(capacity);
        buffer.extend_from_slice(b"previous contents");
        return_unlocked(&mut pool, buffer);
        if capacity > MAX_RETAINED_CAPACITY {
            assert_eq!(pool.rejected_oversized, 1);
            assert_eq!(pool.bytes, 0);
        } else {
            let class = CLASSES.iter().rposition(|&size| size <= capacity).unwrap();
            let buffer = take_unlocked(&mut pool, class).unwrap();
            assert!(buffer.is_empty());
            assert_eq!(buffer.capacity(), capacity);
            assert_eq!(pool.bytes, 0);
        }
    }
}

#[test]
fn production_acquire_and_drop_bypass_a_held_pool_lock() {
    // Holding this lock in the calling thread makes a blocking fallback deadlock.
    // Counter assertions allow unrelated parallel tests to make progress too.
    let pool = POOL.get_or_init(Mutex::default).lock().unwrap();
    let acquisitions = CONTENDED_ACQUISITIONS.load(Ordering::Relaxed);
    let returns = CONTENDED_RETURNS.load(Ordering::Relaxed);
    let buffer = PooledBuffer::with_capacity(CLASSES[0]);
    assert!(buffer.capacity() >= CLASSES[0]);
    drop(buffer);
    assert!(CONTENDED_ACQUISITIONS.load(Ordering::Relaxed) > acquisitions);
    assert!(CONTENDED_RETURNS.load(Ordering::Relaxed) > returns);
    drop(pool);
}
