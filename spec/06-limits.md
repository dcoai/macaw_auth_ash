# 06 — Known limits {#ash-limits}

## 1. Limits of this release {#ash-known}

Known when v0.1.0 was released (macaw_compose#53):
- **No second factor.** AshAuthentication 4.x has none; the backend refuses every code and the kit's block is pending until 5.0 is final ([00 §3](00-overview.md#ash-second-factor)).
- **`must_change_password` isn't mapped:** every user reports false, so no session owes a password change under this backend. The contract's step exists ([macaw_auth 01 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-steps)); nothing configures a field for it.
- **No generator for the host's resources.** A host writes its user and token resources itself, with the extension, the notifier, a unique identity on the username, and the fields it names in the configuration; the test app's are the worked example.
- **An extra token per password sign-in.** AshAuthentication 4.15's password sign-in always signs a token; `Macaw.Auth.Ash` revokes it at once, quietly ([01 §2](01-backend.md#ash-authenticate)), so each password sign-in leaves a revocation row in the token resource until the expunger removes it at the token's expiry.
- **What the directory says beyond the username, roles and display name isn't stored** ([05 §4](05-ldap-strategy.md#ash-ldap-provision)).

```test:ash-must-change-unmapped
every user under this backend reports must_change_password false, and a fresh session's pending step is nil
```

## 2. Gaps found writing this spec {#ash-gaps}

From the code (v0.1.0); open for the owner's decision:
- **No sign-in throttle.** `Macaw.Auth.Ash.authenticate/2` ignores `:remote_ip` and counts no failures, so under this backend nothing slows password guessing, unless the host adds AshAuthentication's own brute-force protection or a rate limit in front ([01 §2](01-backend.md#ash-authenticate)). The contract says a backend throttles second-factor attempts; nothing says it throttles sign-ins, but the native backend does.
- **The `token_lifetime` ≥ `idle_days` rule is documented, not checked.** A user resource whose tokens live shorter than `idle_days` ends sessions at the JWT's expiry, earlier than the idle period promises ([02 §3](02-sessions.md#ash-sessions-idle)). `Macaw.Auth.Ash.Config` could compare them.
- **`idle_days` is unbounded** (any positive integer), where the native backend's `session_idle_days` is 1..3650.
- **A session for a deleted user raises.** `Macaw.Auth.Ash.Sessions.create/2` loads the user with `{:ok, record} = Ash.get(…)`, so creating a session for a user deleted after sign-in raises `MatchError` rather than returning a refusal (confirmed by reading; the contract's `create_session/2` has no error return).
