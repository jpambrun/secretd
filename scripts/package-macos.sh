#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bundle="$project_root/dist/SecretD.app"
contents="$bundle/Contents"

cargo build --manifest-path "$project_root/Cargo.toml" --release --bin secretd
mkdir -p "$contents/MacOS" "$project_root/dist/bin"
rm -f "$contents/MacOS/secretd-desktop"
cp "$project_root/target/release/secretd" "$contents/MacOS/secretd"
cp "$project_root/packaging/macos/Info.plist" "$contents/Info.plist"
codesign --force --deep --sign - "$bundle"
cp "$contents/MacOS/secretd" "$project_root/dist/bin/secretd"

echo "Created $bundle and dist/bin/secretd from the same executable"
