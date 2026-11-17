//! One-shot faults stay on the test's OS thread and reset during unwinding.
use std::cell::Cell;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Operation {
    ReadEnabled = 1,
    Flush = 2,
    Disable = 4,
    Restore = 8,
}

thread_local! {
    static PENDING: Cell<u8> = const { Cell::new(0) };
}

pub(crate) struct Reset(u8);

impl Drop for Reset {
    fn drop(&mut self) {
        PENDING.with(|pending| pending.set(self.0));
    }
}

pub(crate) fn fail_once(operations: &[Operation]) -> Reset {
    let bits = operations.iter().fold(0, |bits, op| bits | *op as u8);
    Reset(PENDING.with(|pending| pending.replace(bits)))
}

pub(super) fn check(name: &[u8], value: Option<bool>) -> Result<(), String> {
    let operation = match (name, value) {
        (b"thread.tcache.enabled\0", None) => Operation::ReadEnabled,
        (b"thread.tcache.enabled\0", Some(false)) => Operation::Disable,
        (b"thread.tcache.enabled\0", Some(true)) => Operation::Restore,
        (b"thread.tcache.flush\0", None) => Operation::Flush,
        _ => return Ok(()),
    };
    if PENDING.with(|pending| {
        let bits = pending.get();
        pending.set(bits & !(operation as u8));
        bits & operation as u8 != 0
    }) {
        Err(format!("injected {operation:?} failure"))
    } else {
        Ok(())
    }
}
