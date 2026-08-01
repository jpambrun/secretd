#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bundle="$project_root/dist/secretd.app"
contents="$bundle/Contents"
legacy_bundle=$(find "$project_root/dist" -maxdepth 1 -type d -name 'SecretD.app' -print -quit 2>/dev/null || true)

if [ -n "$legacy_bundle" ]; then
    rename_staging="$project_root/dist/.secretd-app-case-migration"
    if [ -e "$rename_staging" ]; then
        echo "Cannot rename $legacy_bundle while $rename_staging exists" >&2
        exit 1
    fi
    mv "$legacy_bundle" "$rename_staging"
    mv "$rename_staging" "$bundle"
fi

cargo build --manifest-path "$project_root/Cargo.toml" --release --bin secretd
mkdir -p "$contents/MacOS" "$project_root/dist/bin"
rm -f "$contents/MacOS/secretd-desktop"
cp "$project_root/target/release/secretd" "$contents/MacOS/secretd"
cp "$project_root/packaging/macos/Info.plist" "$contents/Info.plist"
codesign --force --deep --sign - "$bundle"
cp "$contents/MacOS/secretd" "$project_root/dist/bin/secretd"

echo "Created $bundle and dist/bin/secretd from the same executable"
