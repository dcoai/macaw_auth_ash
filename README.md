<img src="brand/logo/macaw_scarlet.svg" alt="The Macaw logo, a scarlet macaw in flight" width="128">

# macaw_auth_ash

> **This software is a very early release, and not ready for general use.**

Public home: [github.com/dcoai/macaw_auth_ash](https://github.com/dcoai/macaw_auth_ash) · Docs: [hexdocs.pm](https://hexdocs.pm/macaw_auth_ash)

A [macaw_auth](https://github.com/dcoai/macaw_auth) backend over [AshAuthentication](https://hexdocs.pm/ash_authentication) 4.x: a host's Ash user and token resources behind the `Macaw.Auth` contract, so an Ash host gets macaw_auth's plugs, LiveView hooks, steps and revocation push without a second user table.

| Module | What it does |
|---|---|
| `Macaw.Auth.Ash` | the backend: sign-in through the resource's strategies, sessions in its token resource |
| `Macaw.Auth.Ash.TokenResource` | the token resource extension: the actions sessions need |
| `Macaw.Auth.Ash.Notifier` | tells open pages of a revocation made through Ash directly |
| `Macaw.Auth.Ash.Strategy.Ldap` | macaw_auth's LDAP source as an AshAuthentication strategy, provisioning users at first sign-in |

## Configuration

```elixir
# mix.exs
{:macaw_auth_ash, "~> 0.3.2"}

# config.exs
config :macaw_auth, backend: Macaw.Auth.Ash, pubsub: MyApp.PubSub

config :macaw_auth, Macaw.Auth.Ash,
  user_resource: MyApp.Accounts.User,
  token_resource: MyApp.Accounts.Token,     # default: the user resource's
  domain: MyApp.Accounts,                   # default: the user resource's
  strategies: [:password, :nas],            # or strategy: :password; tried in order
  roles_from: :roles,                       # an attribute (list of strings), or {m, f} of the record
  username_field: :email,                   # default: the first strategy's identity field
  display_name_field: :name,                # optional
  source_field: :source,                    # optional; without it every user is "local"
  disabled_field: :disabled_at,             # optional, boolean or timestamp
  idle_days: 14                             # 1..3650, at most the user resource's token_lifetime
```

The token resource takes this library's extension and notifier (without the notifier, a verifier warns at compile time and the configuration refuses it when it loads):

```elixir
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
    notifiers: [Macaw.Auth.Ash.Notifier]
end
```

and the user resource's `token_lifetime` is a session's absolute limit, so set it to at least `idle_days`. macaw_auth's application checks the whole configuration when it starts (the backend's `check_config!/0`), so any fault in it refuses boot, naming the fault, rather than failing the first sign-in. Then the router uses `Macaw.Auth.Plug` and `Macaw.Auth.Live` as with any backend.

## How it maps

- **Sign-in.** `authenticate/2` runs the configured strategies in order; the first that knows the user decides, so a wrong password never falls through to another source. A wrong password and an unknown user are one refusal, `:invalid_credentials`, taking one hash each (AshAuthentication's password sign-in hashes against nothing for an unknown user). A disabled user is refused `:disabled`, only after the right password.
- **Sessions are stored user tokens.** A session is an AshAuthentication user JWT, signed with the resource's own secret, whose row in the token resource holds the `jti` (the session's id), never the JWT, with macaw_auth's metadata (last use, address, agent, steps) in `extra_data`. Revoking sets the row's purpose to `"revocation"`, the state AshAuthentication's own checks refuse, so a revocation means the same to both. Idle sessions expire after `idle_days`; use is recorded at most hourly, and a re-check never extends a session.
- **The notifier.** A revocation through Ash rather than `Macaw.Auth.revoke/2` (AshAuthentication's sign-out, a revoke by jti, log-out-everywhere) still reaches the user's open pages at once: `Macaw.Auth.Ash.Notifier` announces revocations it is notified of, and the extension announces log-out-everywhere's bulk revocation, which sends no notifications.
- **LDAP.** `ldap :nas do source {MyApp.Directory, :nas, []} ... end` in the user resource's `strategies` signs a user in against a directory with macaw_auth's escaping, TLS rules (`allow_plaintext: false`), required group and role mapping, provisions their row at first sign-in, and re-derives their roles at every one. A row another source owns is never taken over.

## The second factor is unsupported

AshAuthentication 4.x, the stable line this library targets, has no TOTP strategy (5.0, a release candidate as this is written, adds one). So under this backend every user reports `second_factor: :none`, no session owes the step, and `Macaw.Auth.verify_second_factor/3` refuses with `{:error, :unsupported}`. The conformance kit runs with its second-factor block pending, saying so in every test run, rather than passed by a stub. A host that needs a second factor today uses macaw_auth's native backend; this one gains it when AshAuthentication 5.0 is final.

## Tests

`mix test` runs macaw_auth's conformance kit against a test app (an Ash domain on AshSqlite, in `test/support`), plus this backend's own tests. The `:ldap` tests run against macaw's OpenLDAP fixture image when `MACAW_AUTH_LDAP_HOST` names it:

```sh
docker run -d --rm --name macaw-auth-ldap -p 127.0.0.1:3391:389 -p 127.0.0.1:3638:636 macaw-ldap-test
MACAW_AUTH_LDAP_HOST=localhost MACAW_AUTH_LDAP_PORT=3391 MACAW_AUTH_LDAPS_PORT=3638 mix test --include ldap
docker stop macaw-auth-ldap
```

Part of [Macaw](https://github.com/dcoai/macaw) (spec/00 §4, host libraries). Released on Hex.
