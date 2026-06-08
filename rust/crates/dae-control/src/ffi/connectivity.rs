use super::*;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_apply_event_by_id(
    owner: *mut OutboundConnectivityMapOwner,
    map_id: u32,
    event: FfiConnectivityEvent,
    report: *mut FfiOutboundConnectivityOwnerApplyReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull outbound connectivity owner required".to_owned());
        }
        let event = ConnectivityEvent {
            key: ConnectivityKey {
                outbound: event.outbound,
                l4proto: event.l4proto,
                ipversion: event.ipversion,
            },
            alive: event.alive != 0,
            is_init: event.is_init != 0,
            dryrun: event.dryrun != 0,
        };
        let owner = unsafe { &mut *owner };
        let applied = owner.apply_event_by_id(map_id, event).map_err(|err| {
            format!("apply outbound connectivity event via Rust in-process: {err}")
        })?;
        if !report.is_null() {
            unsafe {
                *report = FfiOutboundConnectivityOwnerApplyReport {
                    map_id: applied.map_id,
                    map_id_changed: u8::from(applied.map_id_changed),
                    accepted: u8::from(applied.accepted),
                    changed: u8::from(applied.changed),
                    skipped: u8::from(applied.skipped),
                    entries_updated: applied.entries_updated,
                    len: applied.len,
                };
            }
        }
        Ok(())
    })
}
