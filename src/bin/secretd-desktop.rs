#[path = "../app.rs"]
mod app;
#[path = "../icon.rs"]
mod icon;
#[path = "../runtime.rs"]
mod runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    runtime::run()
}
