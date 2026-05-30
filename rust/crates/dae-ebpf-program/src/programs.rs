use aya_ebpf::bindings::{__sk_buff, bpf_sock, bpf_sock_addr};

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_ingress_l2")]
pub extern "C" fn tproxy_lan_ingress_l2(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_ingress_l3")]
pub extern "C" fn tproxy_lan_ingress_l3(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_egress_l2")]
pub extern "C" fn tproxy_lan_egress_l2(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/lan_egress_l3")]
pub extern "C" fn tproxy_lan_egress_l3(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_ingress_l2")]
pub extern "C" fn tproxy_wan_ingress_l2(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_ingress_l3")]
pub extern "C" fn tproxy_wan_ingress_l3(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_egress_l2")]
pub extern "C" fn tproxy_wan_egress_l2(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/wan_egress_l3")]
pub extern "C" fn tproxy_wan_egress_l3(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/dae0peer_ingress")]
pub extern "C" fn tproxy_dae0peer_ingress(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier/dae0_ingress")]
pub extern "C" fn tproxy_dae0_ingress(_ctx: *mut __sk_buff) -> i32 {
    crate::tproxy::chain_next()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_create")]
pub extern "C" fn tproxy_wan_cg_sock_create(_ctx: *mut bpf_sock) -> i32 {
    crate::cgroup::allow()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_release")]
pub extern "C" fn tproxy_wan_cg_sock_release(_ctx: *mut bpf_sock) -> i32 {
    crate::cgroup::allow()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn tproxy_wan_cg_connect4(_ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::allow()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn tproxy_wan_cg_connect6(_ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::allow()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn tproxy_wan_cg_sendmsg4(_ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::allow()
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn tproxy_wan_cg_sendmsg6(_ctx: *mut bpf_sock_addr) -> i32 {
    crate::cgroup::allow()
}
