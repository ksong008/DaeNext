use super::*;
pub(crate) fn parse_tproxy_listener_open_handoff_options(
    args: &[String],
) -> Result<TproxyListenerOpenHandoffOptions, String> {
    let mut map_id = None;
    let mut port = None;
    let mut handoff_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener open-handoff --map-id",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "tproxy-listener open-handoff --port",
                )?)
            }
            "--handoff-fd" => {
                handoff_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener open-handoff --handoff-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--handoff-fd=") => handoff_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener open-handoff argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerOpenHandoffOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener open-handoff --map-id".to_owned())?,
        port: port.ok_or_else(|| "missing tproxy-listener open-handoff --port".to_owned())?,
        handoff_fd: handoff_fd
            .ok_or_else(|| "missing tproxy-listener open-handoff --handoff-fd".to_owned())?,
    })
}

pub(crate) fn parse_tproxy_listener_update_map_options(
    args: &[String],
) -> Result<TproxyListenerUpdateMapOptions, String> {
    let mut map_id = None;
    let mut tcp_fd = None;
    let mut udp_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener update-map --map-id",
                )?)
            }
            "--tcp-fd" => {
                tcp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --tcp-fd",
                )?)
            }
            "--udp-fd" => {
                udp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --udp-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--tcp-fd=") => tcp_fd = Some(parse_value(arg)?),
            _ if arg.starts_with("--udp-fd=") => udp_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener update-map argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerUpdateMapOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener update-map --map-id".to_owned())?,
        tcp_fd: tcp_fd.ok_or_else(|| "missing tproxy-listener update-map --tcp-fd".to_owned())?,
        udp_fd: udp_fd.ok_or_else(|| "missing tproxy-listener update-map --udp-fd".to_owned())?,
    })
}
