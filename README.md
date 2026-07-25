# SecretD (Rust)

SecretD is a native local secret vault. It keeps an encrypted vault on disk, runs in the system
tray, and asks for approval before the `secretd` CLI can release a secret to another process.

This implementation is file- and protocol-compatible with the Deno implementation in
`../secretd`.

## Development

```sh
just check
just run
```

In another terminal:

```sh
cargo run --bin secretd -- get service/account/token
```

On macOS, build `dist/SecretD.app` and `dist/bin/secretd` with:

```sh
just package-macos
```

The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-256-GCM. Secret names and values
are encrypted together. Temporary grants and activity history exist only in memory.
