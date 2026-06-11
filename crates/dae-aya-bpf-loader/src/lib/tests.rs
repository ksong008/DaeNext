#[cfg(test)]
mod tests {

    #[path = "loader_contracts.rs"]
    mod loader_contracts;

    #[path = "trace_loader.rs"]
    mod trace_loader;

    #[path = "attach_commands.rs"]
    mod attach_commands;

    #[path = "map_parsers.rs"]
    mod map_parsers;

    #[path = "serve_handlers.rs"]
    mod serve_handlers;

    #[path = "primitives.rs"]
    mod primitives;
}
