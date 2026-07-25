use std::io::Write;

use secretd::{ipc::get_secret, paths::cli_runtime_path};

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    if matches!(command.as_deref(), Some("--help" | "-h")) {
        usage(0);
    }
    let Some(secret) = args.next() else {
        usage(1);
    };
    if command.as_deref() != Some("get") || args.next().is_some() {
        usage(1);
    }
    if let Err(error) = run(&secret) {
        eprintln!("secretd: {error}");
        std::process::exit(1);
    }
}

fn run(secret: &str) -> Result<(), String> {
    let value = get_secret(&cli_runtime_path()?, secret)?;
    std::io::stdout()
        .write_all(value.as_bytes())
        .map_err(|error| error.to_string())
}

fn usage(code: i32) -> ! {
    eprintln!("Usage: secretd get <secret-name>");
    std::process::exit(code);
}
