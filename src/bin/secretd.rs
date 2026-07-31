use std::{
    io::Write,
    process::{Command, Stdio},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use secretd::{ipc::get_secret, paths::cli_runtime_path};

#[path = "../app.rs"]
mod app;
#[path = "../icon.rs"]
mod icon;
#[path = "../runtime.rs"]
mod runtime;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Desktop { detach: bool },
    Get(String),
    Help,
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match mode(&arguments) {
        Ok(Mode::Desktop { detach }) => {
            let result = if detach {
                launch_desktop(&arguments)
            } else {
                runtime::run().map_err(|error| error.to_string())
            };
            if let Err(error) = result {
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
        [] => Ok(Mode::Desktop { detach: true }),
        [argument] if argument == "--show" => Ok(Mode::Desktop { detach: true }),
        [command] if command == "desktop" => Ok(Mode::Desktop { detach: true }),
        [command, argument] if command == "desktop" && argument == "--show" => {
            Ok(Mode::Desktop { detach: true })
        }
        [command, argument] if command == "desktop" && argument == "--foreground" => {
            Ok(Mode::Desktop { detach: false })
        }
        [command, foreground, show]
            if command == "desktop" && foreground == "--foreground" && show == "--show" =>
        {
            Ok(Mode::Desktop { detach: false })
        }
        [command, secret] if command == "get" => Ok(Mode::Get(secret.clone())),
        [argument] if matches!(argument.as_str(), "--help" | "-h" | "help") => Ok(Mode::Help),
        _ => Err(()),
    }
}

fn launch_desktop(arguments: &[String]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the SecretD executable: {error}"))?;
    let mut command = Command::new(executable);
    command
        .arg("desktop")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if arguments.iter().any(|argument| argument == "--show") {
        command.arg("--show");
    }
    #[cfg(unix)]
    command.process_group(0);
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("could not start the desktop process: {error}"))
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
  secretd desktop --foreground
                             Run attached for diagnostics
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
        assert_eq!(mode(&arguments(&[])), Ok(Mode::Desktop { detach: true }));
        assert_eq!(
            mode(&arguments(&["--show"])),
            Ok(Mode::Desktop { detach: true })
        );
        assert_eq!(
            mode(&arguments(&["desktop"])),
            Ok(Mode::Desktop { detach: true })
        );
        assert_eq!(
            mode(&arguments(&["desktop", "--foreground"])),
            Ok(Mode::Desktop { detach: false })
        );
        assert_eq!(
            mode(&arguments(&["desktop", "--foreground", "--show"])),
            Ok(Mode::Desktop { detach: false })
        );
        assert_eq!(
            mode(&arguments(&["get", "service/token"])),
            Ok(Mode::Get("service/token".into()))
        );
        assert_eq!(mode(&arguments(&["--help"])), Ok(Mode::Help));
        assert_eq!(mode(&arguments(&["get"])), Err(()));
    }
}
