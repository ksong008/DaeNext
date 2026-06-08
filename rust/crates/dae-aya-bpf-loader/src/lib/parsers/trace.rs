use super::*;
pub(crate) fn parse_trace_load_pin_options(
    args: &[String],
) -> Result<TraceLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut pin_root = None;
    let mut ip_version = None;
    let mut l4_proto = None;
    let mut port = None;
    let mut ringbuf_size = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => object = Some(parse_next_path(&mut iter, "trace-loader --object")?),
            "--pin-root" => pin_root = Some(parse_next_path(&mut iter, "trace-loader --pin-root")?),
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(&mut iter, "trace-loader --ip-version")?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(&mut iter, "trace-loader --l4-proto")?)
            }
            "--port" => port = Some(parse_next::<u16>(&mut iter, "trace-loader --port")?),
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(&mut iter, "trace-loader --ringbuf-size")?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ => return Err(format!("unsupported trace-loader load-pin argument: {arg}")),
        }
    }
    Ok(TraceLoaderLoadPinOptions {
        object: object.ok_or_else(|| "missing trace-loader load-pin --object".to_owned())?,
        pin_root: pin_root.ok_or_else(|| "missing trace-loader load-pin --pin-root".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader load-pin --ip-version".to_owned())?,
        l4_proto: l4_proto.ok_or_else(|| "missing trace-loader load-pin --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader load-pin --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader load-pin --ringbuf-size".to_owned())?,
    })
}

pub(crate) fn parse_trace_attach_ringbuf_smoke_options(
    args: &[String],
) -> Result<TraceLoaderAttachRingbufSmokeOptions, String> {
    let mut object = None;
    let mut target = None;
    let mut program_name = Some("kprobe_skb_1".to_owned());
    let mut ip_version = Some(4_u8);
    let mut l4_proto = Some(6_u16);
    let mut port = Some(443_u16);
    let mut ringbuf_size = Some(65_536_u32);
    let mut trigger = Some(TraceLoaderAttachSmokeTrigger::LoopbackUdp);
    let mut trigger_count = Some(4_u32);
    let mut poll_attempts = Some(50_u32);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --object",
                )?)
            }
            "--target" => {
                target = Some(
                    next_value(&mut iter, "trace-loader attach-ringbuf-smoke --target")?.to_owned(),
                )
            }
            "--program-name" => {
                program_name = Some(
                    next_value(
                        &mut iter,
                        "trace-loader attach-ringbuf-smoke --program-name",
                    )?
                    .to_owned(),
                )
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ip-version",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --l4-proto",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --port",
                )?)
            }
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ringbuf-size",
                )?)
            }
            "--trigger" => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(next_value(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger",
                )?)?)
            }
            "--trigger-count" => {
                trigger_count = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger-count",
                )?)
            }
            "--poll-attempts" => {
                poll_attempts = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --poll-attempts",
                )?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--target=") => target = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ if arg.starts_with("--trigger=") => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(split_value(arg)?)?)
            }
            _ if arg.starts_with("--trigger-count=") => trigger_count = Some(parse_value(arg)?),
            _ if arg.starts_with("--poll-attempts=") => poll_attempts = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported trace-loader attach-ringbuf-smoke argument: {arg}"
                ));
            }
        }
    }
    Ok(TraceLoaderAttachRingbufSmokeOptions {
        object: object
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --object".to_owned())?,
        target: target
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --target".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --program-name".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ip-version".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ringbuf-size".to_owned())?,
        trigger: trigger
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --trigger".to_owned())?,
        trigger_count: trigger_count.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --trigger-count".to_owned()
        })?,
        poll_attempts: poll_attempts.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --poll-attempts".to_owned()
        })?,
    })
}
