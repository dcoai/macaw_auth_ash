# 00 — Overview {#ash-overview}

## 1. What macaw_auth_ash holds {#ash-holds}

AshAuthentication is the strongest existing authentication library for Elixir (password, magic link, OAuth2/OIDC, API keys, passkeys, audit-log brute-force protection, maintained by the Ash core team), but adopting it means becoming an Ash client: the user is an Ash resource under an Ash domain on an Ash data layer. Seven of the family's apps are plain Ecto. So `macaw_auth` is built natively, **and** gives an Ash project a way to drop AshAuthentication in (macaw_compose#32, owner amendment of 2026-10-26). `macaw_auth_ash` is that way, in its own library, so `macaw_auth` never depends on Ash. It holds:
- **the backend,** `Macaw.Auth.Ash`: the [macaw_auth contract](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-contract) over a host's AshAuthentication user and token resources, with its configuration `Macaw.Auth.Ash.Config` ([01](01-backend.md)) and its sessions `Macaw.Auth.Ash.Sessions` ([02](02-sessions.md));
- **a token-resource extension,** `Macaw.Auth.Ash.TokenResource`, adding the actions sessions need ([03](03-token-resource.md));
- **the revocation announcers,** `Macaw.Auth.Ash.Notifier` and `Macaw.Auth.Ash.AnnounceRevocation`, so a token revoked through Ash directly still reaches the user's open pages ([04](04-notifier.md));
- **the other direction:** `Macaw.Auth.Ash.Strategy.Ldap`, macaw_auth's native LDAP source as an AshAuthentication strategy, so an Ash project gets that LDAP sign-in (escaping, TLS rules, group checks, diagnostics) from the one implementation. It is the strategy AshAuthentication lacks ([05](05-ldap-strategy.md)).

An Ash host keeps Ash's registration, magic links, passkeys and policies; Macaw needs only the contract.

## 2. Versions and dependencies {#ash-dependencies}

- **`macaw_auth` v0.1.1,** by git tag: the contract, the plugs and hooks it serves, the conformance kit it runs, the LDAP source its strategy wraps, `Macaw.Auth.announce_revoked/2`, which v0.1.1 added for this library's notifier (macaw_compose#53), and `Macaw.Auth.Native.Throttle`, the native sign-in throttle the backend reuses as it is ([01 §2.1](01-backend.md#ash-throttle)); macaw_auth's application starts it whichever backend is configured. Phoenix, LiveView and PubSub come through it.
- **`ash_authentication` `~> 4.15`, the stable line** (4.15.0 locked), and **`ash` `~> 3.7`** (3.37.2 locked). AshAuthentication's TOTP strategy exists only in 5.0, a release candidate when this was built; the versions were checked before the work started, and the stable line was chosen (macaw_compose#53).
- **OTP applications:** `:logger`, `:crypto`, `:eldap`, `:ssl`, `:public_key`.
- **Test only:** `ash_sqlite` and `ecto_sqlite3`. The test app (`test/support`) is an Ash domain on AshSqlite: a user resource with a password strategy, the LDAP strategy and log-out-everywhere, and a token resource with this library's extension and notifier. The `:ldap` tests need macaw's OpenLDAP fixture directory and run when `MACAW_AUTH_LDAP_HOST` names it.
- **Elixir** 1.18 or newer.

It is released by git tag (v0.1.1: the sign-in throttle and the checked session settings, macaw_compose#76).

```elixir
config :macaw_auth, backend: Macaw.Auth.Ash, pubsub: MyApp.PubSub

config :macaw_auth, Macaw.Auth.Ash,
  user_resource: MyApp.Accounts.User,
  strategies: [:password, :nas],
  roles_from: :roles,
  disabled_field: :disabled_at,
  idle_days: 14
```

## 3. The second factor is pending {#ash-second-factor}

AshAuthentication 4.x has no TOTP strategy. So under this backend:
- **every user reports `second_factor: :none`,** and no session owes the step;
- **`verify_second_factor/3` refuses every code** with `{:error, :unsupported}`;
- **the conformance kit runs with its second-factor block pending,** saying why in every run (`"AshAuthentication 4.x has no TOTP strategy; supported when 5.0 is final"`), rather than passed by a stub ([macaw_auth 04 §3](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/04-conformance.md#auth-kit-pending)). Its fixtures refuse to make a user with a second factor other than `:none`.

The contract doesn't change when 5.0 is final; only this backend gains it. A host that needs a second factor today uses macaw_auth's native backend.

```test:ash-kit
the kit run against Macaw.Auth.Ash passes its thirteen tests outside the second factor, and reports the five second-factor tests skipped as pending with the reason above
```

```test:ash-unsupported
Macaw.Auth.verify_second_factor(session.id, "123456") under this backend is {:error, :unsupported}
```

## 4. Where it fits {#ash-fits}

Like `macaw_auth`, it sits outside Macaw's composition model, among the host libraries ([macaw_compose 00 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-packaging)). The host's router uses `Macaw.Auth.Plug` and `Macaw.Auth.Live` as with any backend ([macaw_auth 02](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/02-plugs.md#auth-plug), [03](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/03-live.md#auth-live)). No Ash-based adopter exists yet, so it has no adoption proposal (macaw_compose#32).

```test:ash-plug
through Macaw.Auth.Plug, a session cookie's token resolves to its user, roles and session (remote_ip kept) with no pending step; a revoked session's request is sent to "/login" and loses the token from the session
```
