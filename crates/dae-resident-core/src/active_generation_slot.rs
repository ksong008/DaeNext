use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use crate::PublicationEpoch;

#[derive(Debug)]
struct ActiveGenerationSlotInner<T> {
    generation: RwLock<Option<Arc<T>>>,
    publication: AtomicU64,
    publication_signal: tokio::sync::watch::Sender<PublicationEpoch>,
}

#[derive(Debug)]
pub struct ActiveGenerationSlot<T> {
    inner: Arc<ActiveGenerationSlotInner<T>>,
}

impl<T> Clone for ActiveGenerationSlot<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> ActiveGenerationSlot<T> {
    pub fn new(generation: Arc<T>) -> Self {
        let (publication_signal, _) = tokio::sync::watch::channel(PublicationEpoch::INITIAL);
        Self {
            inner: Arc::new(ActiveGenerationSlotInner {
                generation: RwLock::new(Some(generation)),
                publication: AtomicU64::new(PublicationEpoch::INITIAL.get()),
                publication_signal,
            }),
        }
    }

    pub fn load(&self) -> Arc<T> {
        self.inner
            .generation
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone)
            .expect("resident active generation slot was cleared during terminal shutdown")
    }

    pub fn load_versioned(&self) -> (PublicationEpoch, Arc<T>) {
        let active = self
            .inner
            .generation
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = active
            .as_ref()
            .map(Arc::clone)
            .expect("resident active generation slot was cleared during terminal shutdown");
        let publication = PublicationEpoch::new(self.inner.publication.load(Ordering::Acquire));
        (publication, generation)
    }

    pub fn subscribe_publication(&self) -> tokio::sync::watch::Receiver<PublicationEpoch> {
        self.inner.publication_signal.subscribe()
    }

    pub fn publish(&self, generation: Arc<T>) -> Arc<T> {
        let mut active = self
            .inner
            .generation
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = active
            .replace(generation)
            .expect("resident active generation slot was cleared before publication");
        let publication =
            PublicationEpoch::new(self.inner.publication.fetch_add(1, Ordering::Release)).next();
        self.inner.publication_signal.send_replace(publication);
        previous
    }

    pub fn clear(&self) -> Option<Arc<T>> {
        self.inner
            .generation
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn loaded_arc_remains_pinned_across_publication() {
        let first = Arc::new(String::from("first"));
        let slot = ActiveGenerationSlot::new(Arc::clone(&first));
        let (first_publication, pinned) = slot.load_versioned();
        let retired = slot.publish(Arc::new(String::from("second")));
        let (second_publication, active) = slot.load_versioned();

        assert_eq!(pinned.as_str(), "first");
        assert!(Arc::ptr_eq(&pinned, &first));
        assert!(Arc::ptr_eq(&retired, &first));
        assert_eq!(active.as_str(), "second");
        assert!(second_publication > first_publication);
    }

    #[tokio::test]
    async fn publication_notifies_waiters() {
        let first = Arc::new(String::from("first"));
        let slot = ActiveGenerationSlot::new(Arc::clone(&first));
        let mut publication = slot.subscribe_publication();
        assert_eq!(*publication.borrow_and_update(), PublicationEpoch::INITIAL);

        let previous = slot.publish(Arc::new(String::from("second")));

        tokio::time::timeout(Duration::from_secs(1), publication.changed())
            .await
            .expect("generation publication must wake waiters")
            .expect("active generation slot must retain its publication sender");
        assert_eq!(*publication.borrow_and_update(), PublicationEpoch::new(2));
        assert!(Arc::ptr_eq(&previous, &first));
    }

    #[test]
    fn clear_releases_shared_generation_owner() {
        let generation = Arc::new(String::from("generation"));
        let slot = ActiveGenerationSlot::new(Arc::clone(&generation));
        let cloned_slot = slot.clone();

        let cleared = slot.clear().expect("active generation must be present");

        assert!(Arc::ptr_eq(&cleared, &generation));
        assert!(cloned_slot.clear().is_none());
        assert_eq!(Arc::strong_count(&generation), 2);
    }

    #[test]
    fn publication_wrap_is_change_only() {
        let slot = ActiveGenerationSlot::new(Arc::new(String::from("first")));
        slot.inner.publication.store(u64::MAX, Ordering::Release);

        slot.publish(Arc::new(String::from("second")));

        let (publication, active) = slot.load_versioned();
        assert_eq!(publication, PublicationEpoch::new(0));
        assert_eq!(active.as_str(), "second");
    }
}
