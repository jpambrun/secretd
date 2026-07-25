#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bundle="$project_root/dist/SecretD.app"
contents="$bundle/Contents"

cargo build --manifest-path "$project_root/Cargo.toml" --release --bins
mkdir -p "$contents/MacOS" "$project_root/dist/bin"
cp "$project_root/target/release/secretd-desktop" "$contents/MacOS/secretd-desktop"
cp "$project_root/target/release/secretd" "$project_root/dist/bin/secretd"
cp "$project_root/packaging/macos/Info.plist" "$contents/Info.plist"
codesign --force --deep --sign - "$bundle"

echo "Created $bundle and $project_root/dist/bin/secretd"
