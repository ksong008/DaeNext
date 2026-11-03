use super::*;
use std::{cell::Cell, rc::Rc};

#[derive(Default)]
struct Owner {
    maps: [bool; 3],
    writes: usize,
    attaches: Vec<&'static str>,
}

fn prepare(owner: &mut Owner, fail: &mut Option<usize>) -> Result<(), String> {
    for index in 0..owner.maps.len() {
        if *fail == Some(index) {
            return Err(format!("map writer failed at {index}"));
        }
        owner.maps[index] = true;
        owner.writes += 1;
    }
    Ok(())
}

fn attach(prepared: PreparedRouting<'_, Owner>, _: &mut Option<usize>) -> Result<(), String> {
    for role in [
        "cgroup",
        "wan-ingress",
        "wan-egress",
        "lan-ingress",
        "lan-egress",
    ] {
        assert_eq!(prepared.0.maps, [true; 3], "{role} before complete prefill");
        prepared.0.attaches.push(role);
    }
    Ok(())
}

#[test]
fn startup_routing_precedes_physical_attach() {
    let mut owner = Owner::default();
    with_prepared_routing(&mut owner, &mut None, prepare, attach).unwrap();
    assert_eq!(owner.writes, 3);
    assert_eq!(owner.attaches.len(), 5);
}

#[test]
fn startup_routing_failure_prevents_physical_attach() {
    for failure in 0..3 {
        let mut owner = Owner::default();
        let result = with_prepared_routing(&mut owner, &mut Some(failure), prepare, attach);
        assert!(result.unwrap_err().contains(&failure.to_string()));
        assert!(owner.attaches.is_empty());
        assert_eq!(owner.writes, failure);
    }
}

#[test]
fn startup_routing_ready_is_bound_to_loaded_owner() {
    // Owner identity is the exclusive borrow, not a reusable numeric map ID.
    // A fresh/rebound owner must run its own writer even with identical inputs.
    let mut old = Owner::default();
    let mut replacement = Owner::default();
    for owner in [&mut old, &mut replacement] {
        let address = std::ptr::from_ref(&*owner);
        with_prepared_routing(owner, &mut None, prepare, |ready, context| {
            assert_eq!(std::ptr::from_ref(&*ready.0), address);
            attach(ready, context)
        })
        .unwrap();
        assert_eq!(owner.writes, 3);
    }
    assert_eq!(old.attaches, replacement.attaches);
}

#[test]
fn startup_routing_preparation_is_shared_within_one_attach_phase() {
    let mut owner = Owner::default();
    with_prepared_routing(&mut owner, &mut None, prepare, |ready, _| {
        for _ in 0..3 {
            assert_eq!(ready.0.maps, [true; 3]);
            assert_eq!(ready.0.writes, 3);
            ready.0.attaches.push("lan");
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(owner.attaches, ["lan"; 3]);
    assert_eq!(owner.writes, 3);
}

#[test]
fn startup_routing_does_not_bypass_listener_publication() {
    for (worker_present, published) in [(false, false), (false, true), (true, false)] {
        let mut owner = Owner::default();
        let result = with_prepared_routing(&mut owner, &mut None, prepare, |ready, _| {
            validate_started_dataplane(
                &json!({"status": "pass", "enabled": true}),
                worker_present,
                published,
            )?;
            ready.0.attaches.push("host");
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(owner.maps, [true; 3]);
        assert!(owner.attaches.is_empty());
    }
}

#[test]
fn startup_routing_failure_releases_its_resources() {
    struct Resource(Rc<Cell<usize>>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for fail_prepare in [false, true] {
        let releases = Rc::new(Cell::new(0));
        let mut owner = Resource(Rc::clone(&releases));
        let result: Result<(), String> = with_prepared_routing(
            &mut owner,
            &mut (),
            |_, _| {
                if fail_prepare {
                    Err("prepare".into())
                } else {
                    Ok(())
                }
            },
            |_, _| Err("attach".into()),
        );
        assert!(result.is_err());
        // Neither error path retains ownership beyond the caller's cleanup.
        drop(owner);
        assert_eq!(releases.get(), 1);
    }
}
