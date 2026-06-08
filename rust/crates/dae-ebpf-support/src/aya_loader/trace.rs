use super::*;
pub fn load_pin_aya_trace_object(
    options: AyaTraceLoaderOptions<'_>,
) -> Result<AyaTraceLoadPinReport, String> {
    if !TRACE_CORE_SIDELOAD_ENABLED {
        return Err(trace_core_sideload_gate_report().disabled_reason.to_owned());
    }

    let map_pin_root = options.pin_root.join("maps");
    let program_pin_root = options.pin_root.join("programs");
    fs::create_dir_all(&map_pin_root)
        .map_err(|err| format!("create trace map pin root failed: {err}"))?;
    fs::create_dir_all(&program_pin_root)
        .map_err(|err| format!("create trace program pin root failed: {err}"))?;

    let mut loader = aya::EbpfLoader::new();
    loader.allow_unsupported_maps();
    let trace_config = AyaTraceConfig {
        port: crate::htons(options.port),
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        pad: 0,
    };
    loader.set_global("tracing_cfg", &trace_config, true);
    loader.set_max_entries("events", options.ringbuf_size);

    let mut ebpf = loader
        .load_file(options.object)
        .map_err(|err| format!("aya trace object load failed: {err:?}"))?;

    let mut maps = Vec::new();
    for name in ["events", "skb_addresses"] {
        let map = ebpf
            .map(name)
            .ok_or_else(|| format!("aya trace map not found: {name}"))?;
        let path = map_pin_root.join(name);
        remove_existing_pin(&path)?;
        map.pin(&path)
            .map_err(|err| format!("pin trace map {name} failed: {err:?}"))?;
        maps.push(AyaPinnedObject {
            name: name.to_owned(),
            path,
        });
    }

    let mut programs = Vec::new();
    for name in [
        "kprobe_skb_1",
        "kprobe_skb_2",
        "kprobe_skb_3",
        "kprobe_skb_4",
        "kprobe_skb_5",
        "kprobe_skb_lifetime_termination",
    ] {
        let program = ebpf
            .program_mut(name)
            .ok_or_else(|| format!("aya trace program not found: {name}"))?;
        ensure_trace_program_loaded(name, program)?;
        let path = program_pin_root.join(name);
        remove_existing_pin(&path)?;
        program
            .pin(&path)
            .map_err(|err| format!("pin trace program {name} failed: {err:?}"))?;
        programs.push(AyaPinnedObject {
            name: name.to_owned(),
            path,
        });
    }

    Ok(AyaTraceLoadPinReport {
        object: options.object.to_owned(),
        pin_root: options.pin_root.to_owned(),
        map_pin_root,
        program_pin_root,
        maps,
        programs,
        port: options.port,
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        ringbuf_size: options.ringbuf_size,
    })
}

pub fn attach_ringbuf_smoke_aya_trace_object(
    options: AyaTraceAttachRingbufSmokeOptions<'_>,
) -> Result<AyaTraceAttachRingbufSmokeReport, String> {
    if !TRACE_CORE_SIDELOAD_ENABLED {
        return Err(trace_core_sideload_gate_report().disabled_reason.to_owned());
    }

    let mut loader = aya::EbpfLoader::new();
    loader.allow_unsupported_maps();
    let trace_config = AyaTraceConfig {
        port: crate::htons(options.port),
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        pad: 0,
    };
    loader.set_global("tracing_cfg", &trace_config, true);
    loader.set_max_entries("events", options.ringbuf_size);

    let mut ebpf = loader
        .load_file(options.object)
        .map_err(|err| format!("aya trace object load failed: {err:?}"))?;
    let events_map = ebpf
        .take_map("events")
        .ok_or_else(|| "aya trace events ringbuf map not found".to_owned())?;
    let mut ringbuf = RingBuf::try_from(events_map)
        .map_err(|err| format!("open trace events ringbuf failed: {err:?}"))?;

    let _link_id = {
        let program = ebpf
            .program_mut(options.program_name)
            .ok_or_else(|| format!("aya trace program not found: {}", options.program_name))?;
        match program {
            Program::KProbe(program) => {
                program.load().map_err(|err| {
                    format!(
                        "load trace kprobe program {} failed: {err:?}",
                        options.program_name
                    )
                })?;
                program.attach(options.target, 0).map_err(|err| {
                    format!(
                        "attach trace kprobe program {} to {} failed: {err:?}",
                        options.program_name, options.target
                    )
                })?
            }
            other => {
                return Err(format!(
                    "program {} has unsupported type {:?} for trace attach smoke",
                    options.program_name,
                    other.prog_type()
                ));
            }
        }
    };

    trigger_trace_smoke(options.trigger, options.trigger_count)?;

    let mut events_seen = 0_u32;
    let mut first_event_len = 0_usize;
    let mut first_event_pc_nonzero = false;
    let mut first_event_skb_nonzero = false;
    for _ in 0..options.poll_attempts.max(1) {
        while let Some(item) = ringbuf.next() {
            events_seen = events_seen.saturating_add(1);
            if first_event_len == 0 {
                first_event_len = item.len();
                first_event_pc_nonzero = read_ne_u64(&item, 0).is_some_and(|value| value != 0);
                first_event_skb_nonzero = read_ne_u64(&item, 8).is_some_and(|value| value != 0);
            }
        }
        if events_seen > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if events_seen == 0 {
        return Err(format!(
            "trace attach ringbuf smoke observed no events for target {} using trigger {}",
            options.target,
            options.trigger.as_str()
        ));
    }

    Ok(AyaTraceAttachRingbufSmokeReport {
        object: options.object.to_owned(),
        target: options.target.to_owned(),
        program_name: options.program_name.to_owned(),
        trigger: options.trigger,
        trigger_count: options.trigger_count,
        poll_attempts: options.poll_attempts,
        events_seen,
        first_event_len,
        first_event_pc_nonzero,
        first_event_skb_nonzero,
    })
}

pub(super) fn ensure_program_loaded_for_go_adoption(
    name: &str,
    program: &mut Program,
) -> Result<(), String> {
    if program.fd().is_ok() {
        return Ok(());
    }
    match program {
        Program::SchedClassifier(program) => program
            .load()
            .map_err(|err| format!("load sched classifier program {name} failed: {err:?}")),
        Program::CgroupSock(program) => program
            .load()
            .map_err(|err| format!("load cgroup sock program {name} failed: {err:?}")),
        Program::CgroupSockAddr(program) => program
            .load()
            .map_err(|err| format!("load cgroup sock_addr program {name} failed: {err:?}")),
        other => Err(format!(
            "program {name} has unsupported type {:?} for dae Go adoption",
            other.prog_type()
        )),
    }
}

pub(super) fn ensure_trace_program_loaded(name: &str, program: &mut Program) -> Result<(), String> {
    if program.fd().is_ok() {
        return Ok(());
    }
    match program {
        Program::KProbe(program) => program
            .load()
            .map_err(|err| format!("load trace kprobe program {name} failed: {err:?}")),
        other => Err(format!(
            "program {name} has unsupported type {:?} for trace loader",
            other.prog_type()
        )),
    }
}

pub(super) fn trigger_trace_smoke(
    trigger: AyaTraceAttachSmokeTrigger,
    trigger_count: u32,
) -> Result<(), String> {
    let count = trigger_count.max(1);
    match trigger {
        AyaTraceAttachSmokeTrigger::LoopbackUdp => {
            let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .map_err(|err| format!("bind loopback UDP trigger socket failed: {err}"))?;
            for _ in 0..count {
                let _ = socket
                    .send_to(&[0xda, 0xe0], (std::net::Ipv4Addr::LOCALHOST, 9))
                    .map_err(|err| format!("send loopback UDP trigger packet failed: {err}"))?;
            }
            Ok(())
        }
        AyaTraceAttachSmokeTrigger::OpenProcSelfStat => {
            for _ in 0..count {
                let _ = fs::read("/proc/self/stat")
                    .map_err(|err| format!("open proc self stat trigger failed: {err}"))?;
            }
            Ok(())
        }
    }
}

pub(super) fn read_ne_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let bytes = bytes.get(offset..offset + mem::size_of::<u64>())?;
    let mut out = [0_u8; mem::size_of::<u64>()];
    out.copy_from_slice(bytes);
    Some(u64::from_ne_bytes(out))
}
