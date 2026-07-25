# SecretD (Rust)

SecretD is a native local secret vault distributed as one executable. With no arguments it runs in
the system tray; its `get` command asks the desktop process for approval before releasing a secret.

This implementation is file- and protocol-compatible with the Deno implementation in
`../secretd`.

## Development

```sh
just check
just run
```

In another terminal:

```sh
target/release/secretd get service/account/token
```

Use `secretd --show` to launch the tray service with its window open.

On macOS, package the same executable as both `dist/SecretD.app/Contents/MacOS/secretd` and the
standalone `dist/bin/secretd` with:

```sh
just package-macos
```

The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-256-GCM. Secret names and values
are encrypted together. Temporary grants and activity history exist only in memory.
