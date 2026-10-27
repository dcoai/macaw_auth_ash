# 01 — The backend {#ash-backend}

`Macaw.Auth.Ash` implements every `Macaw.Auth.Backend` callback ([macaw_auth 01 §2](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-backend)) over a host's AshAuthentication user and token resources:

| Callback | Implemented by |
|---|---|
| `authenticate/2` | `Macaw.Auth.Ash.authenticate/2`: the configured strategies, in order (§2) |
| `create_session/2`, `fetch_session/2`, `fetch_session_by_id/2`, `list_sessions/2`, `revoke_sessions/2`, `complete_step/3` | `Macaw.Auth.Ash.Sessions` ([02](02-sessions.md)) |
| `verify_second_factor/3` | `{:error, :unsupported}` always ([00 §3](00-overview.md#ash-second-factor)) |

**Every read and write is made with `authorize?: false`:** this is the authentication layer itself, before there is an actor to authorize.

## 1. Configuration {#ash-config}

`config :macaw_auth, Macaw.Auth.Ash, …`, read and checked by `Macaw.Auth.Ash.Config.get/0` (which is `Macaw.Auth.Ash.Config.parse!/1` of the application's setting) **on every call,** not cached: it is a handful of lookups, and a host or a test that changes it sees the change at once. **A fault raises `ArgumentError`,** `"config :macaw_auth, Macaw.Auth.Ash: <fault>"`: it is a deployment bug, not a refusal.

| Key | What | Default | Checked |
|---|---|---|---|
| `user_resource` | the host's user resource | required | an Ash resource |
| `token_resource` | the token resource | the user resource's (`authentication_tokens_token_resource`) | an Ash resource **with the `Macaw.Auth.Ash.TokenResource` extension** ([03](03-token-resource.md)) |
| `domain` | the Ash domain the calls use | the user resource's | |
| `strategies` | AshAuthentication strategy names on the user resource, tried in order (§2) | `[:password]` | a non-empty list; each a password strategy or a `Macaw.Auth.Ash.Strategy.Ldap` |
| `strategy` | one strategy name, in place of `strategies` | | not both |
| `roles_from` | an attribute holding a list of strings, or `{module, function}` called with the user record | `:roles` | an attribute of the user resource, or `function/1` exported |
| `username_field` | the attribute the contract's `username` is read from | the first strategy's `identity_field` | an attribute |
| `display_name_field` | the attribute for `display_name` | none | an attribute |
| `source_field` | the attribute naming the owning source | none: every user is `"local"` | an attribute |
| `disabled_field` | a boolean or timestamp attribute: set means disabled | none | an attribute |
| `idle_days` | how long a session may go unused ([02 §3](02-sessions.md#ash-sessions-idle)) | 14 | a positive integer |

And the user resource needs **a single-attribute primary key:** sessions name their user by the subject's one primary-key value.

The faults read: `"unknown keys [:color_scheme]"`, `"user_resource is required"`, `"user_resource: <m> is not an Ash resource"`, `"token_resource is required (<user> names none)"`, `"token_resource <m> needs the Macaw.Auth.Ash.TokenResource extension"`, `"set one of strategy (a name) or strategies (a non-empty list)"`, `"strategy :nope is not on <user>"`, `"strategy :x is a <struct>"` (a strategy of another kind), `"user_resource needs a single-attribute primary key, not [...]"`, `"<key>: :nope is not an attribute of <user>"`, `"roles_from: M.f/1 is not defined"`, `"roles_from: <v> is neither an attribute nor {module, function}"`, `"idle_days: 0 is not a positive integer"`.

```test:ash-config-faults
parse!/1 with strategies: [:nope], an unknown key :color_scheme, disabled_field: :nope and idle_days: 0 each raises ArgumentError naming the fault
```

```test:ash-config-defaults
parse!(user_resource: User) takes the token resource and domain from the user resource, the :password strategy, and username_field :username (the strategy's identity field)
```

## 2. Signing in {#ash-authenticate}

`Macaw.Auth.Ash.authenticate/2` checks `%{username: _, password: _}` against the configured strategies, in order: `{:ok, %Macaw.Auth.User{}}`, or `{:error, :invalid_credentials | :disabled}`.
- **The username is trimmed;** the password is passed as given (AshAuthentication's own arguments are Ash strings, which it trims at registration and sign-in alike, so a password with surrounding spaces still matches).
- **An empty username or password** (or a missing or non-string one) never reaches a strategy: a hash's time is spent against nothing (the first password strategy's `hash_provider.simulate/0`, when there is one) and the refusal is `:invalid_credentials`.
- **The first strategy that knows the user decides,** as macaw_auth's native sources do ([macaw_auth 06 §2](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/06-native-sources.md#auth-chain)): its acceptance signs the user in; its refusal is final, so a wrong password never falls through to the next strategy, or one account's password could be tried against another's; a strategy that doesn't know the user passes the attempt on. With none knowing the user, the last refusal stands.
  - **A password strategy** runs AshAuthentication's sign-in action (`AshAuthentication.Strategy.action(strategy, :sign_in, %{identity => username, password_field => password})`). On a refusal, **it knows the user when a row with that identity has a hashed password** (an LDAP-provisioned row has none, so the attempt passes on to the directory).
  - **An LDAP strategy** runs `Macaw.Auth.Ash.Strategy.Ldap.sign_in/4` ([05 §3](05-ldap-strategy.md#ash-ldap-sign-in)), whose refusals say whether they are final.
- **A disabled user** (`disabled_field` set) **is refused `:disabled`, only after the right password,** so the refusal tells a guesser nothing; a wrong password for them is `:invalid_credentials`.
- **One refusal otherwise:** a wrong password and an unknown user are both `:invalid_credentials`, and **take the same time:** AshAuthentication's password sign-in hashes against nothing when no user matches (`hash_provider.simulate/0`), as it hashes against the user's hash for a wrong password. A provisioning refusal (`:username_taken`) is `:invalid_credentials` too.

**The token AshAuthentication's sign-in signs is revoked at once.** AshAuthentication 4.15's password sign-in always signs a user token for the user it accepts (its preparation has no way to ask for none). The session is `create_session/2`'s ([02](02-sessions.md)), so that token is revoked immediately, quietly (the notifier ignores it, [04 §1](04-notifier.md#ash-notifier)): it never leaves `authenticate/2`, and revoked it is no credential even to AshAuthentication. Each password sign-in therefore leaves one revocation row in the token resource until the expunger removes it ([06](06-limits.md#ash-limits)).

**No throttle.** `:remote_ip` is ignored, and nothing counts failures: a sign-in is never `:throttled` under this backend ([06 §2](06-limits.md#ash-gaps)).

Every attempt emits `[:macaw_auth, :ash, :authenticate]` with `%{count: 1}` and `%{result: :ok | :error, reason, strategy: name | nil, user_id: id | nil}` (`reason` the strategy's own, `:empty` for an empty field, `:disabled`); **never the username or password.**

```test:ash-authenticate-fields
a user with roles ["admin", "viewer"] and display name "Ada" signs in as %Macaw.Auth.User{username: <theirs>, display_name: "Ada", roles: ["admin", "viewer"], source: "local", disabled: false, second_factor: :none}
```

```test:ash-authenticate-disabled
a disabled user is {:error, :disabled} with the right password and {:error, :invalid_credentials} with a wrong one
```

```test:ash-authenticate-empty
an empty password, an empty username, %{} and %{username: 1} are each {:error, :invalid_credentials}
```

```test:ash-authenticate-trim
the username with surrounding spaces signs in; the password with surrounding spaces signs in (AshAuthentication trims it); the password upper-cased is :invalid_credentials
```

```test:ash-authenticate-timing
five refusals of an unknown user take more than a quarter of the time of five refusals of a wrong password (each costs a hash)
```

```test:ash-authenticate-discarded-token
after a password sign-in, the token resource holds one row, purpose "revocation", the user has no sessions, and a subscriber hears nothing
```

## 3. The user {#ash-to-user}

`Macaw.Auth.Ash.to_user/2` (`record`, `config`) makes a user record the contract's `%Macaw.Auth.User{}`:
- `id`: the primary key's value;
- `username`: `username_field`'s value, as a string;
- `display_name`: `display_name_field`'s, or nil;
- `source`: `source_field`'s, else `"local"`;
- `roles`: `roles_from`'s attribute, or `module.function(record)`; nil is `[]`;
- `disabled`: true when `disabled_field` holds anything but nil or false (true, or any timestamp);
- `second_factor`: `:none` ([00 §3](00-overview.md#ash-second-factor)); `must_change_password`: false ([06](06-limits.md#ash-limits)); `extra`: `%{}`.

```test:ash-roles-function
with roles_from: {M, :shouted} upper-casing the record's roles, a user with ["viewer"] signs in with roles ["VIEWER"]
```
