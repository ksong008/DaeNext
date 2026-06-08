use super::*;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_routing_owner_new() -> *mut RoutingMapOwner {
    Box::into_raw(Box::<RoutingMapOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_routing_owner_free(owner: *mut RoutingMapOwner) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_new() -> *mut DomainRoutingOwner {
    Box::into_raw(Box::<DomainRoutingOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_free(owner: *mut DomainRoutingOwner) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_new()
-> *mut OutboundConnectivityMapOwner {
    Box::into_raw(Box::<OutboundConnectivityMapOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_free(
    owner: *mut OutboundConnectivityMapOwner,
) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}
