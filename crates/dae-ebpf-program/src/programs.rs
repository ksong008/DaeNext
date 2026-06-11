use aya_ebpf::bindings::{__sk_buff, bpf_sock, bpf_sock_addr};

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_ingress_l2")]
pub extern "C" fn tproxy_lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::lan_ingress(ctx, crate::packet::ETH_HLEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_ingress_l3")]
pub extern "C" fn tproxy_lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::lan_ingress(ctx, 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_egress_l2")]
pub extern "C" fn tproxy_lan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::lan_egress(ctx, crate::packet::ETH_HLEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_egress_l3")]
pub extern "C" fn tproxy_lan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::lan_egress(ctx, 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_ingress_l2")]
pub extern "C" fn tproxy_wan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::wan_ingress(ctx, crate::packet::ETH_HLEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_ingress_l3")]
pub extern "C" fn tproxy_wan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::wan_ingress(ctx, 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_egress_l2")]
pub extern "C" fn tproxy_wan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::wan_egress(ctx, crate::packet::ETH_HLEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_egress_l3")]
pub extern "C" fn tproxy_wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::wan_egress(ctx, 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/dae0peer_ingress")]
pub extern "C" fn tproxy_dae0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::dae0peer_ingress(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/dae0_ingress")]
pub extern "C" fn tproxy_dae0_ingress(ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::dae0_ingress(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_create")]
pub extern "C" fn tproxy_wan_cg_sock_create(ctx: *mut bpf_sock) -> i32 {
    crate::cgroup::update_sock(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_release")]
pub extern "C" fn tproxy_wan_cg_sock_release(ctx: *mut bpf_sock) -> i32 {
    crate::cgroup::release_sock(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn tproxy_wan_cg_connect4(ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::update_sock_addr(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn tproxy_wan_cg_connect6(ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::update_sock_addr(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn tproxy_wan_cg_sendmsg4(ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::update_sock_addr(ctx)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn tproxy_wan_cg_sendmsg6(ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::update_sock_addr(ctx)
}
