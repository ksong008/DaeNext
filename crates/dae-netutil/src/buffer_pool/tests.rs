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

#[test]
fn concurrent_return_is_bounded_and_oversized_storage_is_rejected() {
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
    for (bin, size) in pool.bins.iter().zip(CLASSES) {
        assert!(bin.len() <= PER_CLASS_LIMIT);
        assert!(
            bin.iter()
                .all(|buffer| buffer.capacity() == size && buffer.is_empty())
        );
    }
}
