homebrew_rustup_bin := "/opt/homebrew/opt/rustup/bin"
install_dir := env_var_or_default("SECRETD_INSTALL_DIR", env_var("HOME") + "/bin")

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

install: build
    mkdir -p "{{install_dir}}"
    install -m 755 target/release/secretd "{{install_dir}}/secretd"
    @echo "Installed secretd to {{install_dir}}/secretd"

package-macos:
    sh scripts/package-macos.sh
