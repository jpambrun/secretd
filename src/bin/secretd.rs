use std::io::Write;

use secretd::{ipc::get_secret, paths::cli_runtime_path};

#[path = "../app.rs"]
mod app;
#[path = "../icon.rs"]
mod icon;
#[path = "../runtime.rs"]
mod runtime;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Desktop,
    Get(String),
    Help,
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match mode(&arguments) {
        Ok(Mode::Desktop) => {
            if let Err(error) = runtime::run() {
                eprintln!("secretd: {error}");
                std::process::exit(1);
            }
        }
        Ok(Mode::Get(secret)) => {
            if let Err(error) = get(&secret) {
                eprintln!("secretd: {error}");
                std::process::exit(1);
            }
        }
        Ok(Mode::Help) => usage(0),
        Err(()) => usage(1),
    }
}

fn mode(arguments: &[String]) -> Result<Mode, ()> {
    match arguments {
        [] => Ok(Mode::Desktop),
        [argument] if argument == "--show" => Ok(Mode::Desktop),
        [command] if command == "desktop" => Ok(Mode::Desktop),
        [command, argument] if command == "desktop" && argument == "--show" => Ok(Mode::Desktop),
        [command, secret] if command == "get" => Ok(Mode::Get(secret.clone())),
        [argument] if matches!(argument.as_str(), "--help" | "-h" | "help") => Ok(Mode::Help),
        _ => Err(()),
    }
}

fn get(secret: &str) -> Result<(), String> {
    let value = get_secret(&cli_runtime_path()?, secret)?;
    std::io::stdout()
        .write_all(value.as_bytes())
        .map_err(|error| error.to_string())
}

fn usage(code: i32) -> ! {
    eprintln!(
        "Usage:
  secretd                    Run the tray application
  secretd --show             Open the desktop window
  secretd get <secret-name>  Request a secret"
    );
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::{Mode, mode};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn dispatches_desktop_and_cli_modes() {
        assert_eq!(mode(&arguments(&[])), Ok(Mode::Desktop));
        assert_eq!(mode(&arguments(&["--show"])), Ok(Mode::Desktop));
        assert_eq!(mode(&arguments(&["desktop"])), Ok(Mode::Desktop));
        assert_eq!(
            mode(&arguments(&["get", "service/token"])),
            Ok(Mode::Get("service/token".into()))
        );
        assert_eq!(mode(&arguments(&["--help"])), Ok(Mode::Help));
        assert_eq!(mode(&arguments(&["get"])), Err(()));
    }
}
