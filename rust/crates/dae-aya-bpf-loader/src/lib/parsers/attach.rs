use super::*;
pub(crate) fn parse_cgroup_monitor_attach_pin_options(
    args: &[String],
) -> Result<CgroupMonitorAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut cgroup_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --link-root",
                )?)
            }
            "--cgroup-path" => {
                cgroup_path = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --cgroup-path",
                )?)
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--cgroup-path=") => cgroup_path = Some(parse_path_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported cgroup-monitor attach-pin argument: {arg}"
                ));
            }
        }
    }
    Ok(CgroupMonitorAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --link-root".to_owned())?,
        cgroup_path: cgroup_path
            .ok_or_else(|| "missing cgroup-monitor attach-pin --cgroup-path".to_owned())?,
    })
}

pub(crate) fn parse_tc_attach_pin_options(args: &[String]) -> Result<TcAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut program_name = None;
    let mut iface = None;
    let mut netns = None;
    let mut direction = None;
    let mut priority = None;
    let mut handle = None;
    let mut backend = None;
    let mut filter_name = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --link-root",
                )?)
            }
            "--program-name" => {
                program_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --program-name")?.to_owned())
            }
            "--iface" => {
                iface = Some(next_value(&mut iter, "tc-attach attach-pin --iface")?.to_owned())
            }
            "--netns" => {
                netns = Some(next_value(&mut iter, "tc-attach attach-pin --netns")?.to_owned())
            }
            "--direction" => {
                direction = Some(parse_tc_attach_direction(next_value(
                    &mut iter,
                    "tc-attach attach-pin --direction",
                )?)?)
            }
            "--priority" => {
                priority = Some(parse_next::<u16>(
                    &mut iter,
                    "tc-attach attach-pin --priority",
                )?)
            }
            "--handle" => {
                handle = Some(parse_next::<u32>(
                    &mut iter,
                    "tc-attach attach-pin --handle",
                )?)
            }
            "--backend" => {
                backend = Some(parse_attach_backend(next_value(
                    &mut iter,
                    "tc-attach attach-pin --backend",
                )?)?)
            }
            "--filter-name" => {
                filter_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --filter-name")?.to_owned())
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--iface=") => iface = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--netns=") => netns = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--direction=") => {
                direction = Some(parse_tc_attach_direction(split_value(arg)?)?)
            }
            _ if arg.starts_with("--priority=") => priority = Some(parse_value(arg)?),
            _ if arg.starts_with("--handle=") => handle = Some(parse_value(arg)?),
            _ if arg.starts_with("--backend=") => {
                backend = Some(parse_attach_backend(split_value(arg)?)?)
            }
            _ if arg.starts_with("--filter-name=") => {
                filter_name = Some(split_value(arg)?.to_owned())
            }
            _ => return Err(format!("unsupported tc-attach attach-pin argument: {arg}")),
        }
    }
    Ok(TcAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing tc-attach attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing tc-attach attach-pin --link-root".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing tc-attach attach-pin --program-name".to_owned())?,
        iface: iface.ok_or_else(|| "missing tc-attach attach-pin --iface".to_owned())?,
        netns,
        direction: direction
            .ok_or_else(|| "missing tc-attach attach-pin --direction".to_owned())?,
        priority: priority.ok_or_else(|| "missing tc-attach attach-pin --priority".to_owned())?,
        handle: handle.ok_or_else(|| "missing tc-attach attach-pin --handle".to_owned())?,
        backend: backend.ok_or_else(|| "missing tc-attach attach-pin --backend".to_owned())?,
        filter_name,
    })
}
