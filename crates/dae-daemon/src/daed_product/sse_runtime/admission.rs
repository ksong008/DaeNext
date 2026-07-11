use super::*;

#[derive(Debug, Default)]
struct ProductSseAdmissionState {
    total: usize,
    per_user: HashMap<i64, usize>,
}

#[derive(Debug)]
pub(super) struct ProductSseAdmission {
    connection_limit: usize,
    per_user_limit: usize,
    state: Mutex<ProductSseAdmissionState>,
}

#[derive(Debug)]
pub(super) struct ProductSseAdmissionLease {
    admission: Arc<ProductSseAdmission>,
    user_id: i64,
}

impl ProductSseAdmission {
    pub(super) fn new(config: ProductSseRuntimeConfig) -> Self {
        Self {
            connection_limit: config.connection_limit,
            per_user_limit: config.per_user_limit,
            state: Mutex::new(ProductSseAdmissionState::default()),
        }
    }

    pub(super) fn acquire(self: &Arc<Self>, user_id: i64) -> io::Result<ProductSseAdmissionLease> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("SSE admission state is unavailable"))?;
        let user_connections = state.per_user.get(&user_id).copied().unwrap_or(0);
        if state.total >= self.connection_limit || user_connections >= self.per_user_limit {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "SSE connection limit reached",
            ));
        }
        state.total = state.total.saturating_add(1);
        state
            .per_user
            .insert(user_id, user_connections.saturating_add(1));
        Ok(ProductSseAdmissionLease {
            admission: Arc::clone(self),
            user_id,
        })
    }

    fn release(&self, user_id: i64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.total = state.total.saturating_sub(1);
        if let Some(connections) = state.per_user.get_mut(&user_id) {
            *connections = connections.saturating_sub(1);
            if *connections == 0 {
                state.per_user.remove(&user_id);
            }
        }
    }
}

impl Drop for ProductSseAdmissionLease {
    fn drop(&mut self) {
        self.admission.release(self.user_id);
    }
}
