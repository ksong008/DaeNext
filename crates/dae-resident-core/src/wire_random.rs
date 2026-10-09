use std::io;

/// Cryptographic wire material must fail closed when the OS entropy source fails.
pub fn fill_wire_random(out: &mut [u8]) -> io::Result<()> {
    getrandom::fill(out).map_err(|error| {
        out.fill(0);
        io::Error::other(format!("secure random source failed: {error}"))
    })
}

/// Bounded, lazily allocated OS-random pool for per-packet salt and nonce material.
/// Consumed bytes are never reused, including after a partially failed refill.
#[derive(Default)]
pub struct WireRandomPool<const CAPACITY: usize> {
    bytes: Vec<u8>,
    offset: usize,
}

impl<const CAPACITY: usize> WireRandomPool<CAPACITY> {
    pub fn fill(&mut self, out: &mut [u8]) -> io::Result<()> {
        self.fill_with(out, fill_wire_random)
    }

    fn fill_with(
        &mut self,
        out: &mut [u8],
        refill: impl FnOnce(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if out.len() > CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "random request exceeds pool capacity",
            ));
        }
        if self.bytes.len().saturating_sub(self.offset) < out.len() {
            self.bytes.resize(CAPACITY, 0);
            if let Err(error) = refill(&mut self.bytes) {
                self.bytes.fill(0);
                self.bytes.clear();
                self.offset = 0;
                return Err(error);
            }
            self.offset = 0;
        }
        let end = self.offset + out.len();
        out.copy_from_slice(&self.bytes[self.offset..end]);
        self.bytes[self.offset..end].fill(0);
        self.offset = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_refill_never_publishes_partial_bytes_and_can_recover() {
        let mut pool = WireRandomPool::<16>::default();
        let mut out = [0xaa; 8];
        assert!(
            pool.fill_with(&mut out, |bytes| {
                bytes[..4].fill(7);
                Err(io::Error::other("injected entropy failure"))
            })
            .is_err()
        );
        assert_eq!(out, [0xaa; 8]);
        assert!(pool.bytes.is_empty());
        pool.fill_with(&mut out, |bytes| {
            bytes.fill(9);
            Ok(())
        })
        .unwrap();
        assert_eq!(out, [9; 8]);
        pool.fill_with(&mut out, |_| panic!("remaining pool bytes must be used"))
            .unwrap();
        assert_eq!(out, [9; 8]);
        assert!(
            pool.fill_with(&mut out, |_| Err(io::Error::other("next refill failed")))
                .is_err()
        );
        assert!(pool.bytes.is_empty());
    }

    #[test]
    fn batched_random_draws_do_not_repeat_consumed_bytes() {
        let mut pool = WireRandomPool::<16>::default();
        let mut out = [0; 8];
        pool.fill_with(&mut out, |bytes| {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(out, [0, 1, 2, 3, 4, 5, 6, 7]);
        pool.fill_with(&mut out, |_| panic!("unexpected refill"))
            .unwrap();
        assert_eq!(out, [8, 9, 10, 11, 12, 13, 14, 15]);
        assert!(pool.bytes.iter().all(|byte| *byte == 0));
        assert!(
            pool.fill_with(&mut [0; 17], |_| panic!(
                "oversized request must be rejected"
            ))
            .is_err()
        );
    }
}
