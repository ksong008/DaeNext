use super::*;
pub(crate) fn parse_map_stats_count_options(
    args: &[String],
) -> Result<Vec<MapStatsCountRequest>, String> {
    let mut maps = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map" => maps.push(parse_map_count_request(next_value(
                &mut iter,
                "map-stats count --map",
            )?)?),
            _ if arg.starts_with("--map=") => {
                maps.push(parse_map_count_request(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported map-stats count argument: {arg}")),
        }
    }
    Ok(maps)
}
