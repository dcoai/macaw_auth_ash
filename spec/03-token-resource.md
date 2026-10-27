# 03 — The token resource {#ash-token-resource}

<!-- surfex: class orientation -->

`Macaw.Auth.Ash.TokenResource` is a Spark DSL extension for the host's AshAuthentication token resource, beside AshAuthentication's own, with this library's notifier:

```elixir
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
    notifiers: [Macaw.Auth.Ash.Notifier]
end
```

AshAuthentication's token resource stores a JWT's `jti` (never the JWT), with `purpose`, `subject`, `expires_at` and an `extra_data` map. A Macaw session is one of those rows ([02 §1](02-sessions.md#ash-sessions-token)). The resource's own actions store a token, and revoke one by token or by jti, but can't update `extra_data` in place, read rows by subject, or revoke a stored row by jti without making it unexpungeable (AshAuthentication's `revoke_jti` sets a thousand-year expiry).

## 1. The actions it adds {#ash-token-actions}

Its transformer runs after AshAuthentication's token transformer, whose actions it extends, and before Ash's own action transformers. It adds, **each only when the resource doesn't already define an action of that name:**
- **`:macaw_auth_read`,** a plain read. **It is the primary read when the resource has none:** log-out-everywhere's bulk update needs a primary read, and a token resource otherwise has none;
- **`:macaw_auth_update`,** an update accepting `extra_data`: a session's use, its steps;
- **`:macaw_auth_revoke`,** an update accepting nothing that sets `purpose` to `"revocation"`, **keeping the row's own expiry,** so the expunger still removes it.

And it puts **`Macaw.Auth.Ash.AnnounceRevocation`** on AshAuthentication's `revoke_all_stored_for_subject` action (when that is an update without it already): that action is how log-out-everywhere revokes, as a bulk update without notifications, so a notifier alone would never hear of it ([04 §2](04-notifier.md#ash-announce-revocation)).

It marks the resource as extended (a persisted `:macaw_auth_ash_token?`), which `Macaw.Auth.Ash.Config` requires of the configured token resource ([01 §1](01-backend.md#ash-config)).

`Macaw.Auth.Ash.TokenResource.read_action/0`, `update_action/0` and `revoke_action/0` name the three actions (`:macaw_auth_read`, `:macaw_auth_update`, `:macaw_auth_revoke`).

```test:ash-token-actions-added
the test app's token resource has :macaw_auth_read (its primary read), :macaw_auth_update accepting extra_data and :macaw_auth_revoke; revoking through it leaves purpose "revocation" and the row's expires_at unchanged
```

```test:ash-token-log-out-everywhere
log-out-everywhere, a bulk update over the primary read, revokes every session of the user, and Macaw lists none
```

## 2. The notifier is required {#ash-token-verifier}

A token resource with this extension needs `Macaw.Auth.Ash.Notifier` among its notifiers: without it, a revocation made through Ash directly would reach open pages only at their next re-check. One without it is:
- **warned of at compile time:** the extension's verifier reports a DSL error at `[:notifiers]` naming the notifier. Spark reports a verifier's error as a compile warning, so the resource still compiles unless the build treats warnings as errors;
- **refused at boot,** whatever the build flags were: `Macaw.Auth.Ash.Config` ([01 §1](01-backend.md#ash-config)) raises `ArgumentError`, `"config :macaw_auth, Macaw.Auth.Ash: token_resource <m> needs Macaw.Auth.Ash.Notifier among its notifiers"`, when it loads, which it first does at boot, through macaw_auth's application calling the backend's `check_config!/0`; so a host configured with such a resource refuses to start. The backend loads its configuration on every call after, so no sign-in or session lookup runs over such a resource.

```test:ash-token-verifier-boot
with backend: Macaw.Auth.Ash and a token resource without the notifier configured, :macaw_auth refuses to start, the ArgumentError "token_resource <m> needs Macaw.Auth.Ash.Notifier among its notifiers"
```

```test:ash-token-verifier-refuses
a token resource declaring the extension without notifiers: [Macaw.Auth.Ash.Notifier] compiles with a warning naming the notifier, and Config.parse! with it as the token resource raises ArgumentError "token_resource <m> needs Macaw.Auth.Ash.Notifier among its notifiers"
```
