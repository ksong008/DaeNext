use crate::CliError;

pub fn get_completion(shell: &str) -> Result<String, CliError> {
    match shell {
        "bash" => Ok("# bash completion for dae\ncomplete -F _dae dae\n".to_owned()),
        "zsh" => Ok("#compdef dae\n# zsh completion for dae\n".to_owned()),
        "fish" => Ok("# fish completion for dae\ncomplete -c dae\n".to_owned()),
        other => Err(CliError::UnsupportedShell(other.to_owned())),
    }
}
