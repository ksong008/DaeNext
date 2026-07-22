use super::*;

pub(super) struct ProductControlAdmission {
    dns_active: AtomicU64,
    direct_http_active: AtomicU64,
    proxy_http_active: AtomicU64,
    dns_limit: u64,
    direct_http_limit: u64,
    proxy_http_limit: u64,
}

impl ProductControlAdmission {
    pub(super) fn new(config: ProductControlRuntimeConfig) -> Self {
        Self {
            dns_active: AtomicU64::new(0),
            direct_http_active: AtomicU64::new(0),
            proxy_http_active: AtomicU64::new(0),
            dns_limit: config.dns_limit as u64,
            direct_http_limit: config.direct_http_limit as u64,
            proxy_http_limit: config.proxy_http_limit as u64,
        }
    }

    pub(super) fn try_acquire(
        self: &Arc<Self>,
        kind: ProductControlTaskKind,
    ) -> Option<ProductControlAdmissionPermit> {
        let (active, limit) = self.state(kind);
        let acquired = active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current.saturating_add(1))
            })
            .is_ok();
        acquired.then(|| ProductControlAdmissionPermit {
            admission: Arc::clone(self),
            kind,
        })
    }

    fn state(&self, kind: ProductControlTaskKind) -> (&AtomicU64, u64) {
        match kind {
            ProductControlTaskKind::Dns => (&self.dns_active, self.dns_limit),
            ProductControlTaskKind::DirectHttp => {
                (&self.direct_http_active, self.direct_http_limit)
            }
            ProductControlTaskKind::ProxyHttp => (&self.proxy_http_active, self.proxy_http_limit),
        }
    }

    pub(super) fn snapshot(&self) -> Value {
        json!({
            "dns": self.dns_active.load(Ordering::Relaxed),
            "directHttp": self.direct_http_active.load(Ordering::Relaxed),
            "proxyHttp": self.proxy_http_active.load(Ordering::Relaxed),
        })
    }
}

pub(super) struct ProductControlAdmissionPermit {
    admission: Arc<ProductControlAdmission>,
    kind: ProductControlTaskKind,
}

impl Drop for ProductControlAdmissionPermit {
    fn drop(&mut self) {
        let (active, _) = self.admission.state(self.kind);
        let previous = active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "product control admission underflow");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_class_admission_is_bounded_and_reusable() {
        let admission = Arc::new(ProductControlAdmission::new(
            ProductControlRuntimeConfig::for_test(),
        ));
        let permit = admission.try_acquire(ProductControlTaskKind::Dns).unwrap();
        assert!(admission.try_acquire(ProductControlTaskKind::Dns).is_none());
        assert_eq!(admission.snapshot()["dns"], json!(1));
        drop(permit);
        assert!(admission.try_acquire(ProductControlTaskKind::Dns).is_some());
    }
}
