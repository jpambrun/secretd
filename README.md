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

Use `secretd --show` to launch the tray service with its window open. Desktop launches detach from
the invoking terminal; use `secretd desktop --foreground` when attached logs are useful for
development or diagnostics.

On macOS, package the same executable as both `dist/SecretD.app/Contents/MacOS/secretd` and the
standalone `dist/bin/secretd` with:

```sh
just package-macos
```

The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-256-GCM. Secret names and values
are encrypted together. Temporary grants and activity history exist only in memory.

## AWS IAM Identity Center

SecretD can own the IAM Identity Center device-login flow without invoking the AWS CLI or storing
SSO settings in `~/.aws/config`.

1. Open **AWS SSO**, enter the access portal URL and IAM Identity Center Region, then sign in with
   the device flow. SecretD discovers the AWS accounts and roles assigned to that identity.
2. Assign a local profile alias to each account you want to expose, and select the discovered roles
   SecretD should offer as read-only and admin. Connection details, discovery results, mappings, and
   OIDC tokens are stored inside the encrypted vault.
3. Add only the non-sensitive credential helper entries to `~/.aws/config`, using those aliases:

```ini
[profile dev]
credential_process = /absolute/path/to/secretd aws credentials dev
region = ca-central-1

[profile staging]
credential_process = /absolute/path/to/secretd aws credentials staging
region = ca-central-1

[profile pre-prod]
credential_process = /absolute/path/to/secretd aws credentials pre-prod
region = ca-central-1

[profile prod]
credential_process = /absolute/path/to/secretd aws credentials prod
region = ca-central-1
```

4. Run tools normally. When a process asks for a configured profile, SecretD shows its verified
   process tree and asks whether to deny the request or issue read-only or admin credentials. If the
   SSO session has expired, SecretD opens its window, displays the AWS verification URL and device
   code, waits for login, and then resumes the original credential request. `secretd aws login`
   remains available for an explicit refresh and account rediscovery.

This supports a saved-plan workflow without a caller-controlled access-level variable:

```sh
terraform plan -out=tfplan  # approve read-only credentials in SecretD
terraform apply tfplan      # approve admin credentials in SecretD
```

The selected role is pinned to that verified process for credential refreshes, but is not reused by
a later Terraform invocation. AWS role credentials remain usable by the approved process until
their AWS-provided expiration time.

The generic secret vault and `get` request remain compatible with the Deno implementation. Vaults
that contain the Rust application's AWS extension require an AWS-aware SecretD version.
