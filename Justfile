homebrew_rustup_bin := "/opt/homebrew/opt/rustup/bin"

export PATH := if path_exists(homebrew_rustup_bin + "/cargo") == "true" {
    homebrew_rustup_bin + ":" + env_var("PATH")
} else {
    env_var("PATH")
}

check:
    cargo fmt -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test

run:
    cargo run --release --bin secretd

build:
    cargo build --release --bin secretd

package-macos:
    sh scripts/package-macos.sh
