use std::io;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::ProductUiRuntime;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ProductUiSessionKey {
    pub(super) user_id: i64,
    page_id: String,
}

impl ProductUiSessionKey {
    pub(super) fn new(user_id: i64, page_id: &str) -> Self {
        Self {
            user_id,
            page_id: page_id.to_owned(),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProductUiSession {
    lease_deadline: Instant,
    pub(super) active_streams: u32,
    closing: bool,
}

#[derive(Debug, Default)]
pub(super) struct ProductUiRegistryState {
    pub(super) sessions: std::collections::HashMap<ProductUiSessionKey, ProductUiSession>,
}

impl ProductUiRuntime {
    pub(super) fn touch_page(&self, user_id: i64, page_id: &str, now: Instant) -> io::Result<()> {
        self.sweep_at(now);
        let key = ProductUiSessionKey::new(user_id, page_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("UI session state is unavailable"))?;
        if let Some(session) = state.sessions.get_mut(&key) {
            session.lease_deadline = now.checked_add(self.lease).unwrap_or(now);
            session.closing = false;
            return Ok(());
        }
        let session_limit = self.session_limit.load(Ordering::Relaxed) as usize;
        let per_user_limit = self.per_user_limit.load(Ordering::Relaxed) as usize;
        let user_sessions = state
            .sessions
            .keys()
            .filter(|existing| existing.user_id == user_id)
            .count();
        if state.sessions.len() >= session_limit || user_sessions >= per_user_limit {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "WebUI session limit reached",
            ));
        }
        state.sessions.insert(
            key,
            ProductUiSession {
                lease_deadline: now.checked_add(self.lease).unwrap_or(now),
                active_streams: 0,
                closing: false,
            },
        );
        let active = state.sessions.len() as u64;
        self.sessions_active.store(active, Ordering::Release);
        self.sessions_peak.fetch_max(active, Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn close_page(&self, user_id: i64, page_id: &str, now: Instant) -> io::Result<bool> {
        let key = ProductUiSessionKey::new(user_id, page_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("UI session state is unavailable"))?;
        let Some(session) = state.sessions.get_mut(&key) else {
            return Ok(false);
        };
        session.closing = true;
        session.lease_deadline = now;
        let removed = session.active_streams == 0;
        if removed {
            state.sessions.remove(&key);
            self.publish_session_count(state.sessions.len());
        }
        Ok(true)
    }

    pub(super) fn close_stream(&self, key: &ProductUiSessionKey, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(session) = state.sessions.get_mut(key) {
            session.active_streams = session.active_streams.saturating_sub(1);
            if session.active_streams == 0 && (session.closing || session.lease_deadline <= now) {
                state.sessions.remove(key);
                self.publish_session_count(state.sessions.len());
            }
        }
    }

    pub(super) fn sweep_at(&self, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let before = state.sessions.len();
        state.sessions.retain(|_, session| {
            session.active_streams > 0 || (!session.closing && session.lease_deadline > now)
        });
        if state.sessions.len() != before {
            self.publish_session_count(state.sessions.len());
        }
    }

    fn publish_session_count(&self, sessions: usize) {
        let previous = self.sessions_active.swap(sessions as u64, Ordering::AcqRel);
        if previous > 0 && sessions == 0 {
            self.drain_epoch.fetch_add(1, Ordering::Relaxed);
        }
    }
}
