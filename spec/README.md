# macaw_auth_ash specification

`macaw_auth_ash` is a [macaw_auth](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/README.md) backend over AshAuthentication: a host's Ash user and token resources behind the `Macaw.Auth` contract, so an Ash host gets macaw_auth's plugs, LiveView hooks, steps and revocation push without a second user table; and macaw_auth's LDAP source as an AshAuthentication strategy. Each Macaw component has its own spec in its own repository (dco-tek/macaw_compose#61); this is `macaw_auth_ash`'s. The family's overview, and where the host libraries sit in it, is in [macaw_compose 00 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-packaging).

| File | Covers | Status |
|---|---|---|
| [00 — Overview](00-overview.md) | what `macaw_auth_ash` holds, its versions and dependencies, the second factor pending until AshAuthentication 5.0 | |
| [01 — The backend](01-backend.md) | `Macaw.Auth.Ash` and `Macaw.Auth.Ash.Config`: every configuration key, sign-in through the resource's strategies, the sign-in throttle, the user's fields, the idle limit reported | implemented (v0.2.1) |
| [02 — Sessions](02-sessions.md) | `Macaw.Auth.Ash.Sessions`: sessions as stored user JWTs, the `jti` as id, Macaw's metadata in `extra_data`, idle expiry and the `token_lifetime` rule, a deleted user's and a revoked session's refusals, revocation both ways | implemented (v0.2.0) |
| [03 — The token resource](03-token-resource.md) | `Macaw.Auth.Ash.TokenResource`: its actions, the primary read, the notifier required (warned of at compile time, refused at load) | implemented (v0.2.1) |
| [04 — Announcing revocations](04-notifier.md) | `Macaw.Auth.Ash.Notifier` and `Macaw.Auth.Ash.AnnounceRevocation`: after commit vs inside the transaction, `Macaw.Auth.announce_revoked/2` | implemented (v0.1.0) |
| [05 — The LDAP strategy](05-ldap-strategy.md) | `Macaw.Auth.Ash.Strategy.Ldap`: the DSL, the struct, its field options checked (warned of at compile time, refused at load), its actions, sign-in, provisioning, what isn't stored | implemented (v0.2.1) |
| [06 — Known limits](06-limits.md) | the second factor, `must_change_password`, no generator, the extra token per password sign-in, and the gaps found writing this spec (none open) | |

Every heading carries an anchor prefixed `ash-`, so links into this spec stay stable when a heading is reworded. Each behavioral rule carries a test hint (a fenced block whose info string is `test:<id>`) that says what a test of it must show.
