use super::*;
use std::ops::{Deref, DerefMut};

#[derive(Default)]
pub(super) struct UdpGenerationPins {
    entries: HashMap<UdpGenerationPinKey, UdpGenerationPin>,
    next_expiry: Option<Instant>,
}

impl UdpGenerationPins {
    pub(super) fn get(&self, key: &UdpGenerationPinKey) -> Option<&UdpGenerationPin> {
        self.entries.get(key)
    }

    pub(super) fn get_mut(&mut self, key: &UdpGenerationPinKey) -> Option<PinUpdate<'_>> {
        Some(PinUpdate {
            pin: self.entries.get_mut(key)?,
            next_expiry: &mut self.next_expiry,
        })
    }

    pub(super) fn insert(&mut self, key: UdpGenerationPinKey, pin: UdpGenerationPin) {
        if !self.entries.contains_key(&key) && self.entries.len() >= UDP_GENERATION_PIN_MAX_ENTRIES
        {
            evict_oldest_udp_generation_pin(&mut self.entries);
        }
        self.next_expiry = Some(
            self.next_expiry
                .map_or(pin.expires_at, |old| old.min(pin.expires_at)),
        );
        self.entries.insert(key, pin);
    }

    pub(super) fn retain(
        &mut self,
        keep: impl FnMut(&UdpGenerationPinKey, &mut UdpGenerationPin) -> bool,
    ) {
        self.entries.retain(keep);
        self.next_expiry = self.entries.values().map(|pin| pin.expires_at).min();
    }

    pub(super) fn as_map(&self) -> &HashMap<UdpGenerationPinKey, UdpGenerationPin> {
        &self.entries
    }
    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.next_expiry
    }
}

pub(super) struct PinUpdate<'a> {
    pin: &'a mut UdpGenerationPin,
    next_expiry: &'a mut Option<Instant>,
}

impl Deref for PinUpdate<'_> {
    type Target = UdpGenerationPin;
    fn deref(&self) -> &Self::Target {
        self.pin
    }
}

impl DerefMut for PinUpdate<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.pin
    }
}

impl Drop for PinUpdate<'_> {
    fn drop(&mut self) {
        // This is a conservative lower bound, not an exact min after extension.
        // An old deadline may wake early; retain recomputes it during maintenance.
        *self.next_expiry = Some(
            self.next_expiry
                .map_or(self.pin.expires_at, |old| old.min(self.pin.expires_at)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u16) -> UdpGenerationPinKey {
        UdpGenerationPinKey {
            peer: SocketAddr::from(([127, 0, 0, 1], id)),
            original_dst: SocketAddr::from(([192, 0, 2, 1], 53)),
        }
    }

    #[test]
    fn mutations_keep_a_conservative_deadline_and_maintenance_recomputes_it() {
        let mut pins = UdpGenerationPins::default();
        let now = Instant::now();
        for step in 0..10_000_u64 {
            let id = (step % 73) as u16;
            if step % 7 == 0 {
                pins.retain(|key, _| key.peer.port() != id);
            } else if let Some(mut pin) = pins.get_mut(&key(id)) {
                pin.expires_at = now + Duration::from_millis((step * 37) % 2000);
            } else {
                pins.insert(
                    key(id),
                    UdpGenerationPin {
                        generation: 1,
                        expires_at: now + Duration::from_millis(step % 2000),
                        route: None,
                    },
                );
            }
            if let Some(actual) = pins.as_map().values().map(|pin| pin.expires_at).min() {
                assert!(pins.next_expiry().is_some_and(|cached| cached <= actual));
            }
        }
        pins.retain(|_, _| false);
        assert!(pins.next_expiry().is_none());
        pins.insert(
            key(1),
            UdpGenerationPin {
                generation: 1,
                expires_at: now,
                route: None,
            },
        );
        assert_eq!(pins.next_expiry(), Some(now));
    }

    #[tokio::test]
    async fn expiry_timer_can_be_disabled_and_rearmed_with_an_earlier_pin() {
        let now = Instant::now();
        let mut pins = UdpGenerationPins::default();
        pins.insert(
            key(1),
            UdpGenerationPin {
                generation: 1,
                expires_at: now + Duration::from_secs(60),
                route: None,
            },
        );
        let timer = time::sleep_until(time::Instant::from_std(pins.next_expiry().unwrap()));
        tokio::pin!(timer);
        pins.retain(|_, _| false);
        assert!(pins.next_expiry().is_none());
        pins.insert(
            key(2),
            UdpGenerationPin {
                generation: 2,
                expires_at: now,
                route: None,
            },
        );
        timer
            .as_mut()
            .reset(time::Instant::from_std(pins.next_expiry().unwrap()));
        time::timeout(Duration::from_secs(1), timer).await.unwrap();
        pins.retain(|_, pin| pin.expires_at > Instant::now());
        assert!(pins.next_expiry().is_none());
    }
}
