use std::cell::RefCell;

use super::*;

#[derive(Default)]
struct Fixture {
    domain: Option<BpfDomainRouting>,
    rules: Vec<BpfMatchSet>,
    lookups: Vec<[u8; 16]>,
}

thread_local! {
    static FIXTURE: RefCell<Fixture> = RefCell::default();
}

// The two map lookup boundaries are replaced only in host unit tests. The
// cache, context initialization and routing callback are the production code.
pub(super) fn lookup_match_set(_map: *mut c_void, index: *const u32) -> *mut BpfMatchSet {
    let index = unsafe { *index } as usize;
    FIXTURE.with(|fixture| {
        fixture
            .borrow_mut()
            .rules
            .get_mut(index)
            .map_or(ptr::null_mut(), ptr::from_mut)
    })
}

pub(super) fn lookup_domain_route(
    _map: *mut c_void,
    ip: *const BpfIpBytes,
) -> *mut BpfDomainRouting {
    FIXTURE.with(|fixture| {
        let mut fixture = fixture.borrow_mut();
        fixture.lookups.push(unsafe { (*ip).u6_addr8 });
        fixture
            .domain
            .as_mut()
            .map_or(ptr::null_mut(), ptr::from_mut)
    })
}

fn install(bits: &[u32]) {
    let mut domain = BpfDomainRouting::default();
    for &bit in bits {
        domain.bitmap[(bit / 32) as usize] |= 1 << (bit % 32);
    }
    FIXTURE.with(|fixture| {
        *fixture.borrow_mut() = Fixture {
            domain: Some(domain),
            ..Fixture::default()
        };
    });
}

fn context(params: &RouteParams) -> RouteCtx {
    let mut ctx = RouteCtx::zeroed();
    unsafe { init_route_ctx(&mut ctx, params) };
    ctx
}

fn lookup_count() -> usize {
    FIXTURE.with(|fixture| fixture.borrow().lookups.len())
}

#[test]
fn domain_cache_reuses_hits_and_unset_bits_in_one_word() {
    install(&[1, 31]);
    let params = RouteParams::zeroed();
    let mut ctx = context(&params);
    for (index, expected) in [(1, true), (2, false), (31, true), (0, false)] {
        assert_eq!(
            unsafe { domain_bitmap_hit_cached(&mut ctx, index) },
            expected
        );
    }
    assert_eq!(lookup_count(), 1);
}

#[test]
fn domain_cache_refreshes_at_word_boundaries_and_last_rule() {
    install(&[31, 32, 63, 64, 1023]);
    let params = RouteParams::zeroed();
    let mut ctx = context(&params);
    for index in [31, 32, 63, 64, 1023] {
        assert!(unsafe { domain_bitmap_hit_cached(&mut ctx, index) });
    }
    assert_eq!(lookup_count(), 4);
}

#[test]
fn domain_miss_is_cached_only_until_the_next_packet() {
    install(&[]);
    FIXTURE.with(|fixture| fixture.borrow_mut().domain = None);
    let mut params = RouteParams::zeroed();
    params.daddr.u6_addr8[15] = 1;
    let mut ctx = context(&params);
    assert!(!unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    FIXTURE.with(|fixture| {
        let mut domain = BpfDomainRouting::default();
        domain.bitmap[0] = 2;
        fixture.borrow_mut().domain = Some(domain);
    });
    assert!(!unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    assert!(!unsafe { domain_bitmap_hit_cached(&mut ctx, 1023) });
    assert_eq!(lookup_count(), 1);
    unsafe { init_route_ctx(&mut ctx, &params) };
    assert!(unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    params.daddr.u6_addr8[15] = 2;
    unsafe { init_route_ctx(&mut ctx, &params) };
    assert!(unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    FIXTURE.with(|fixture| {
        let fixture = fixture.borrow();
        assert_eq!(fixture.lookups.len(), 3);
        assert_eq!(fixture.lookups[0][15], 1);
        assert_eq!(fixture.lookups[1][15], 1);
        assert_eq!(fixture.lookups[2][15], 2);
    });
}

#[test]
fn updated_word_is_observed_on_the_next_packet() {
    install(&[1]);
    let params = RouteParams::zeroed();
    let mut ctx = context(&params);
    assert!(unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    FIXTURE.with(|fixture| fixture.borrow_mut().domain.as_mut().unwrap().bitmap[0] = 0);
    assert!(unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    unsafe { init_route_ctx(&mut ctx, &params) };
    assert!(!unsafe { domain_bitmap_hit_cached(&mut ctx, 1) });
    assert_eq!(lookup_count(), 2);
}

#[test]
fn context_initialization_clears_all_domain_cache_state() {
    let params = RouteParams::zeroed();
    let mut ctx = RouteCtx::zeroed();
    ctx.domain_word = u32::MAX;
    ctx.domain_word_index = 7;
    ctx.domain_absent = 1;
    unsafe { init_route_ctx(&mut ctx, &params) };
    assert_eq!(ctx.domain_word, 0);
    assert_eq!(ctx.domain_word_index, DOMAIN_WORD_NONE);
    assert_eq!(ctx.domain_absent, 0);
}

#[test]
fn cached_domain_rules_preserve_or_and_negation_in_the_routing_callback() {
    for (bits, port, expected) in [
        (vec![1], 80, 7),
        (vec![1, 2], 80, 0),
        (vec![], 443, 7),
        (vec![], 80, 0),
    ] {
        install(&bits);
        let mut port_value = [0; 16];
        port_value[..2].copy_from_slice(&443_u16.to_ne_bytes());
        port_value[2..4].copy_from_slice(&443_u16.to_ne_bytes());
        FIXTURE.with(|fixture| {
            fixture.borrow_mut().rules = vec![
                BpfMatchSet {
                    kind: MATCH_TYPE_PORT,
                    value: port_value,
                    outbound: OUTBOUND_LOGICAL_OR,
                    ..BpfMatchSet::default()
                },
                BpfMatchSet {
                    kind: MATCH_TYPE_DOMAIN_SET,
                    outbound: 0xff,
                    ..BpfMatchSet::default()
                },
                BpfMatchSet {
                    kind: MATCH_TYPE_DOMAIN_SET,
                    not: 1,
                    outbound: 7,
                    ..BpfMatchSet::default()
                },
                BpfMatchSet {
                    kind: MATCH_TYPE_FALLBACK,
                    outbound: 0,
                    ..BpfMatchSet::default()
                },
            ];
        });
        let mut params = RouteParams::zeroed();
        params.h_dport = port;
        let mut ctx = context(&params);
        for index in 0..4 {
            if route_loop_cb(index, ptr::from_mut(&mut ctx).cast()) != 0 {
                break;
            }
        }
        assert_eq!(ctx.result, expected, "bitmap={bits:?}, port={port}");
        assert_eq!(lookup_count(), 1);
    }
}
