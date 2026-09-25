# secretd (Rust)

secretd is a native local secret vault distributed as one executable. With no arguments it runs in
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

On macOS, build and install the single executable with:

```sh
just install
```

Tagged releases publish Linux x86-64 and macOS archives on the
[GitHub releases page](https://github.com/jpambrun/secretd/releases). The Linux build requires GTK 3,
Ayatana AppIndicator, xdo, Wayland, and XKB runtime libraries from the host distribution.

The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-256-GCM. Secret names and values
are encrypted together. Temporary grants and activity history exist only in memory.

## AWS IAM Identity Center

secretd can own the IAM Identity Center device-login flow without invoking the AWS CLI or storing
SSO settings in `~/.aws/config`.

1. Open **AWS SSO**, enter the access portal URL and IAM Identity Center Region, then sign in with
   the device flow. secretd discovers the AWS accounts and roles assigned to that identity.
2. Assign a local profile alias to each account you want to expose, and select the discovered roles
   secretd should offer as read-only and admin. Connection details, discovery results, mappings, and
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

4. Run tools normally. When a process asks for a configured profile, secretd opens a compact,
   independent approval window with its verified process tree and asks whether to deny the request
   or grant read-only or admin credentials. The approval window closes after the decision. If the
   SSO session has expired, secretd opens its main window, displays the AWS verification URL and
   device code, waits for login, and then resumes the original credential request. `secretd aws
   login` remains available for an explicit refresh and account rediscovery.

This supports a saved-plan workflow without a caller-controlled access-level variable:

```sh
terraform plan -out=tfplan  # approve read-only credentials in secretd
terraform apply tfplan      # approve admin credentials in secretd
```

The selected role is pinned to the chosen process boundary and its children. New grants default to
30 minutes, can initially last at most 60 minutes, and can be extended in 15-minute increments from
the active-access screen (up to 60 minutes remaining). A later Terraform invocation does not reuse
the grant unless it is still a descendant of the selected live process boundary. Already-issued AWS
role credentials remain usable until their AWS-provided expiration time; revoking or expiring a
grant prevents secretd from issuing another set automatically. A denial or unanswered request is
remembered for 30 minutes for the same verified process lineage and profile, preventing retry loops
from repeatedly opening approval windows. Active grants and remembered denials appear under
**Grants**, where they can be revoked or unblocked immediately.

The generic secret vault and `get` request remain compatible with the Deno implementation. Vaults
that contain the Rust application's AWS extension require an AWS-aware secretd version.
