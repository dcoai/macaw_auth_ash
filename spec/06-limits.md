# 06 — Known limits {#ash-limits}

## 1. Limits of this release {#ash-known}

Known when v0.1.0 was released (macaw_compose#53):
- **No second factor.** AshAuthentication 4.x has none; the backend refuses every code and the kit's block is pending until 5.0 is final ([00 §3](00-overview.md#ash-second-factor)).
- **`must_change_password` isn't mapped:** every user reports false, so no session owes a password change under this backend. The contract's step exists ([macaw_auth 01 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-steps)); nothing configures a field for it.
- **No generator for the host's resources.** A host writes its user and token resources itself, with the extension, the notifier, a unique identity on the username, and the fields it names in the configuration; the test app's are the worked example.
- **An extra token per password sign-in.** AshAuthentication 4.15's password sign-in always signs a token; `Macaw.Auth.Ash` revokes it at once, quietly ([01 §2](01-backend.md#ash-authenticate)), so each password sign-in leaves a revocation row in the token resource until the expunger removes it at the token's expiry.
- **What the directory says beyond the username, roles and display name isn't stored** ([05 §4](05-ldap-strategy.md#ash-ldap-provision)).
- **A session for a deleted user has no refusal in the contract** (since v0.1.1, macaw_compose#76). `Macaw.Auth.Ash.Sessions.create/2` returns `{:error, :invalid}` for a user deleted after signing in ([02 §1](02-sessions.md#ash-sessions-token)), but `Macaw.Auth.Backend.create_session/2` is typed `{:ok, token, session}` only and `Macaw.Auth.Plug.log_in/3` matches it, so through the plug it still ends in a `MatchError`, in macaw_auth rather than here. Giving the callback an error return is macaw_auth's change.

```test:ash-must-change-unmapped
every user under this backend reports must_change_password false, and a fresh session's pending step is nil
```

## 2. Gaps found writing this spec {#ash-gaps}

None open. The four found in v0.1.0 (no sign-in throttle, the `token_lifetime` ≥ `idle_days` rule unchecked, `idle_days` unbounded, a session for a deleted user raising) were fixed in v0.1.1 (macaw_compose#76): [01 §2.1](01-backend.md#ash-throttle), [01 §1](01-backend.md#ash-config), [02 §1](02-sessions.md#ash-sessions-token).
