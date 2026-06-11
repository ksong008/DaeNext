use super::*;
pub(crate) fn parse_connectivity_map_update_options(
    args: &[String],
) -> Result<ConnectivityMapUpdateOptions, String> {
    let mut map_id = None;
    let mut outbound = None;
    let mut l4_proto = None;
    let mut ip_version = None;
    let mut alive = None;
    let mut is_init = None;
    let mut dryrun = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "connectivity-map update --map-id",
                )?)
            }
            "--outbound" => {
                outbound = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --outbound",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --l4-proto",
                )?)
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --ip-version",
                )?)
            }
            "--alive" => {
                alive = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --alive",
                )?)?)
            }
            "--is-init" => {
                is_init = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --is-init",
                )?)?)
            }
            "--dryrun" => {
                dryrun = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --dryrun",
                )?)?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--outbound=") => outbound = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--alive=") => alive = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--is-init=") => is_init = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--dryrun=") => dryrun = Some(parse_bool(split_value(arg)?)?),
            _ => {
                return Err(format!(
                    "unsupported connectivity-map update argument: {arg}"
                ));
            }
        }
    }
    Ok(ConnectivityMapUpdateOptions {
        map_id: map_id.ok_or_else(|| "missing connectivity-map update --map-id".to_owned())?,
        outbound: outbound
            .ok_or_else(|| "missing connectivity-map update --outbound".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing connectivity-map update --l4-proto".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing connectivity-map update --ip-version".to_owned())?,
        alive: alive.ok_or_else(|| "missing connectivity-map update --alive".to_owned())?,
        is_init: is_init.ok_or_else(|| "missing connectivity-map update --is-init".to_owned())?,
        dryrun: dryrun.ok_or_else(|| "missing connectivity-map update --dryrun".to_owned())?,
    })
}
