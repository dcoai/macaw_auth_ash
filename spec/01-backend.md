# 01 — The backend {#ash-backend}

`Macaw.Auth.Ash` implements every `Macaw.Auth.Backend` callback ([macaw_auth 01 §2](https://github.com/dcoai/macaw_auth/blob/main/spec/01-contract.md#auth-backend)) over a host's AshAuthentication user and token resources:

| Callback | Implemented by |
|---|---|
| `authenticate/2` | `Macaw.Auth.Ash.authenticate/2`: the configured strategies, in order (§2) |
| `create_session/2`, `fetch_session/2`, `fetch_session_by_id/2`, `list_sessions/2`, `revoke_sessions/2`, `complete_step/3` | `Macaw.Auth.Ash.Sessions` ([02](02-sessions.md)) |
| `session_idle_seconds/1` | `Macaw.Auth.Ash.session_idle_seconds/1`: `idle_days` × 86 400, the limit sessions expire by ([02 §3](02-sessions.md#ash-sessions-idle)) |
| `verify_second_factor/3` | `{:error, :unsupported}` always ([00 §3](00-overview.md#ash-second-factor)) |
| `check_config!/0` | `Macaw.Auth.Ash.check_config!/0`: `Macaw.Auth.Ash.Config.get/0`, the whole check, at boot (§1) |

**Every read and write is made with `authorize?: false`:** this is the authentication layer itself, before there is an actor to authorize.

## 1. Configuration {#ash-config}

`config :macaw_auth, Macaw.Auth.Ash, …`, read and checked by `Macaw.Auth.Ash.Config.get/0` (which is `Macaw.Auth.Ash.Config.parse!/1` of the application's setting) **on every call,** not cached: it is a handful of lookups, and a host or a test that changes it sees the change at once. **A fault raises `ArgumentError`,** `"config :macaw_auth, Macaw.Auth.Ash: <fault>"`: it is a deployment bug, not a refusal.

**It is checked at boot.** `Macaw.Auth.Ash.check_config!/0`, the contract's `check_config!/0` ([macaw_auth 01 §2.9](https://github.com/dcoai/macaw_auth/blob/main/spec/01-contract.md#auth-backend-check-config)), runs `get/0`, so every check below (the resources, the strategies and their LDAP fields, the notifier, `idle_days` and the token lifetime) is made, and returns `:ok`; macaw_auth's application calls it when it starts with `backend: Macaw.Auth.Ash`. So **a misconfigured host refuses to start, the `ArgumentError` naming the fault,** rather than starting and failing at its first sign-in; and the configuration is still read on every call after.

| Key | What | Default | Checked |
|---|---|---|---|
| `user_resource` | the host's user resource | required | an Ash resource |
| `token_resource` | the token resource | the user resource's (`authentication_tokens_token_resource`) | an Ash resource **with the `Macaw.Auth.Ash.TokenResource` extension and `Macaw.Auth.Ash.Notifier` among its notifiers** ([03](03-token-resource.md), [03 §2](03-token-resource.md#ash-token-verifier)) |
| `domain` | the Ash domain the calls use | the user resource's | |
| `strategies` | AshAuthentication strategy names on the user resource, tried in order (§2) | `[:password]` | a non-empty list; each a password strategy or a `Macaw.Auth.Ash.Strategy.Ldap` |
| `strategy` | one strategy name, in place of `strategies` | | not both |
| `roles_from` | an attribute holding a list of strings, or `{module, function}` called with the user record | `:roles` | an attribute of the user resource, or `function/1` exported |
| `username_field` | the attribute the contract's `username` is read from | the first strategy's `identity_field` | an attribute |
| `display_name_field` | the attribute for `display_name` | none | an attribute |
| `source_field` | the attribute naming the owning source | none: every user is `"local"` | an attribute |
| `disabled_field` | a boolean or timestamp attribute: set means disabled | none | an attribute |
| `idle_days` | how long a session may go unused ([02 §3](02-sessions.md#ash-sessions-idle)) | 14 | an integer from 1 to 3650 (as the native backend's `session_idle_days`), **and no longer than the user resource's `token_lifetime`** (below) |

And the user resource needs **a single-attribute primary key:** sessions name their user by the subject's one primary-key value; and **every LDAP strategy on it, whether or not `strategies` names it, must name attributes of it** in its field options ([05 §1](05-ldap-strategy.md#ash-ldap-dsl)): AshAuthentication's plug signs in through such a strategy either way, and a disabled field that isn't an attribute would let a disabled user in.

**The token lifetime outlasts the idle period.** The user JWT's expiry is a session's absolute limit ([02 §3](02-sessions.md#ash-sessions-idle)), so a `token_lifetime` shorter than `idle_days` would end sessions before they are idle. `parse!/1` reads the user resource's lifetime (`AshAuthentication.Info.authentication_tokens_token_lifetime/1`, `{amount, :days | :hours | :minutes | :seconds}` once AshAuthentication's transformer has made a bare integer hours) and refuses one shorter than `idle_days` × 86 400 seconds, naming both values; equal is accepted.

The faults read: `"unknown keys [:color_scheme]"`, `"user_resource is required"`, `"user_resource: <m> is not an Ash resource"`, `"token_resource is required (<user> names none)"`, `"token_resource <m> needs the Macaw.Auth.Ash.TokenResource extension"`, `"token_resource <m> needs Macaw.Auth.Ash.Notifier among its notifiers"`, `"set one of strategy (a name) or strategies (a non-empty list)"`, `"strategy :nope is not on <user>"`, `"strategy :x is a <struct>"` (a strategy of another kind), `"user_resource needs a single-attribute primary key, not [...]"`, `"<key>: :nope is not an attribute of <user>"`, `"strategy :corp's disabled_field: :locked_at is not an attribute of <user>"` (any of an LDAP strategy's field options), `"roles_from: M.f/1 is not defined"`, `"roles_from: <v> is neither an attribute nor {module, function}"`, `"idle_days: 0 is not an integer from 1 to 3650"`, and `"idle_days: 31 is longer than <user>'s token_lifetime {30, :days}: sessions would end at the token's expiry before they are idle; set token_lifetime to at least 31 days, or idle_days to at most 30"` (the last clause left out when the lifetime is under a day).

```test:ash-check-config-boot
with backend: Macaw.Auth.Ash and idle_days 0, :macaw_auth refuses to start, the ArgumentError "config :macaw_auth, Macaw.Auth.Ash: idle_days: 0 is not an integer from 1 to 3650"; with the test app's configuration, Macaw.Auth.Ash.check_config!/0 is :ok and :macaw_auth starts
```

```test:ash-config-faults
parse!/1 with strategies: [:nope], an unknown key :color_scheme, disabled_field: :nope and idle_days: 0 each raises ArgumentError naming the fault
```

```test:ash-config-idle-bounds
idle_days 0, 3651, 14.5 and "14" each raise ArgumentError "idle_days: <v> is not an integer from 1 to 3650"; idle_days 1 is accepted
```

```test:ash-config-token-lifetime
with the test user resource's token_lifetime {30, :days}, idle_days 30 is accepted and idle_days 31 raises ArgumentError naming 31 and {30, :days}
```

```test:ash-config-defaults
parse!(user_resource: User) takes the token resource and domain from the user resource, the :password strategy, and username_field :username (the strategy's identity field)
```

## 2. Signing in {#ash-authenticate}

`Macaw.Auth.Ash.authenticate/2` checks `%{username: _, password: _}` against the configured strategies, in order: `{:ok, %Macaw.Auth.User{}}`, or `{:error, :invalid_credentials | :disabled | :throttled}`. Options: `:remote_ip` (a string or an address tuple, formatted as a string; the client's, which `Macaw.Auth.Plug` passes) and `:now` (a `DateTime`, the throttle's clock; default the system clock).
- **The throttle is checked first** (§2.1): while it blocks, nothing below runs.
- **The username is trimmed;** the password is passed as given (AshAuthentication's own arguments are Ash strings, which it trims at registration and sign-in alike, so a password with surrounding spaces still matches).
- **An empty username or password** (or a missing or non-string one) never reaches a strategy: a hash's time is spent against nothing (the first password strategy's `hash_provider.simulate/0`, when there is one) and the refusal is `:invalid_credentials`.
- **The first strategy that knows the user decides,** as macaw_auth's native sources do ([macaw_auth 06 §2](https://github.com/dcoai/macaw_auth/blob/main/spec/06-native-sources.md#auth-chain)): its acceptance signs the user in; its refusal is final, so a wrong password never falls through to the next strategy, or one account's password could be tried against another's; a strategy that doesn't know the user passes the attempt on. With none knowing the user, the last refusal stands.
  - **A password strategy** runs AshAuthentication's sign-in action (`AshAuthentication.Strategy.action(strategy, :sign_in, %{identity => username, password_field => password})`). On a refusal, **it knows the user when a row with that identity has a hashed password** (an LDAP-provisioned row has none, so the attempt passes on to the directory).
  - **An LDAP strategy** runs `Macaw.Auth.Ash.Strategy.Ldap.sign_in/4` ([05 §3](05-ldap-strategy.md#ash-ldap-sign-in)), whose refusals say whether they are final.
- **A disabled user** (`disabled_field` set) **is refused `:disabled`, only after the right password,** so the refusal tells a guesser nothing; a wrong password for them is `:invalid_credentials`.
- **One refusal otherwise:** a wrong password and an unknown user are both `:invalid_credentials`, and **take the same time:** AshAuthentication's password sign-in hashes against nothing when no user matches (`hash_provider.simulate/0`), as it hashes against the user's hash for a wrong password. A provisioning refusal (`:username_taken`) is `:invalid_credentials` too.

**The token AshAuthentication's sign-in signs is revoked at once.** AshAuthentication 4.15's password sign-in always signs a user token for the user it accepts (its preparation has no way to ask for none). The session is `create_session/2`'s ([02](02-sessions.md)), so that token is revoked immediately, quietly (the notifier ignores it, [04 §1](04-notifier.md#ash-notifier)): it never leaves `authenticate/2`, and revoked it is no credential even to AshAuthentication. Each password sign-in therefore leaves one revocation row in the token resource until the expunger removes it ([06](06-limits.md#ash-limits)).

Every attempt emits `[:macaw_auth, :ash, :authenticate]` with `%{count: 1}` and `%{result: :ok | :error, reason, strategy: name | nil, user_id: id | nil}` (`reason` the strategy's own, `:empty` for an empty field, `:disabled`, `:throttled` with strategy and user id nil); **never the username or password.**

```test:ash-authenticate-fields
a user with roles ["admin", "viewer"] and display name "Ada" signs in as %Macaw.Auth.User{username: <theirs>, display_name: "Ada", roles: ["admin", "viewer"], source: "local", disabled: false, second_factor: :none}
```

```test:ash-authenticate-disabled
a disabled user is {:error, :disabled} with the right password and {:error, :invalid_credentials} with a wrong one
```

```test:ash-authenticate-empty
an empty password, an empty username, %{} and %{username: 1} are each {:error, :invalid_credentials}, after one hash verification against nothing (simulate/0)
```

```test:ash-authenticate-trim
the username with surrounding spaces signs in; the password with surrounding spaces signs in (AshAuthentication trims it); the password upper-cased is :invalid_credentials
```

```test:ash-authenticate-timing
a wrong password does one hash verification (valid?/2) and an unknown user one against nothing (simulate/0): the same bcrypt work, checked by what runs, never by timing (#1)
```

```test:ash-authenticate-discarded-token
after a password sign-in, the token resource holds one row, purpose "revocation", the user has no sessions, and a subscriber hears nothing
```

### 2.1 The throttle {#ash-throttle}

**Sign-in failures back off as under the native backend, by the native backend's own throttle,** `Macaw.Auth.Native.Throttle` ([macaw_auth 10](https://github.com/dcoai/macaw_auth/blob/main/spec/10-native-throttle.md#auth-throttle)), used as it is: the same keys, backoff, cap, sweep and table. It depends on nothing of the native backend's (no repo, no configuration): one ETS table owned by a process macaw_auth's application starts whichever backend is configured. Its values are its constants: five free failures, then `2^(n-5)` seconds from the key's last failure, capped at 15 minutes ([macaw_auth 10 §2](https://github.com/dcoai/macaw_auth/blob/main/spec/10-native-throttle.md#auth-throttle-backoff)).
- **Two keys** ([macaw_auth 10 §1](https://github.com/dcoai/macaw_auth/blob/main/spec/10-native-throttle.md#auth-throttle-keys)): **the username,** trimmed and lower-cased (`Alice`, ` alice` and `ALICE` share a count; a case-sensitive identity only shares one count between its case variants, which slows nobody but a guesser), every empty username sharing the one key `:invalid`; and **the address,** the `:remote_ip` passed. **No `:remote_ip`, no address key:** a caller that passes none is throttled by username alone. An attempt waits for the longer of the two keys' waits.
- **While either key waits,** `authenticate/2` is `{:error, :throttled}` **without checking the password** (no strategy runs, so no token is signed and no directory is asked), and the attempt is **not counted.** It still **spends a hash's time,** as an empty field does (the first password strategy's `hash_provider.simulate/0`, bcrypt's `no_user_verify`), so the response time doesn't tell a guesser when the block starts or ends. (A host whose strategies are all LDAP has no password strategy, so a blocked attempt spends nothing there; nor does a checked one hash locally, its cost is the directory's.)
- **Every other refusal counts as a failure** on both keys, as under the native backend: a wrong password, an unknown user, an empty field, a disabled user.
- **A success resets the username's count, never the address's** ([macaw_auth 10 §3](https://github.com/dcoai/macaw_auth/blob/main/spec/10-native-throttle.md#auth-throttle-reset)), so one valid account can't clear its address's count between guesses at others.

```test:ash-throttle-backoff
five wrong passwords from 192.0.2.1 at t0: the right password is :throttled at t0 and at t0 + 999 ms, and signs in at t0 + 1 000 ms
```

```test:ash-throttle-per-address
five unknown usernames from 198.51.100.1: a real user's right password from it is :throttled, and from 198.51.100.2 signs in
```

```test:ash-throttle-per-username
five wrong passwords at ned from five addresses: ned's right password from a sixth is :throttled; oli's from that sixth signs in
```

```test:ash-throttle-normalized
five failures at the username upper-cased with surrounding spaces throttle the username as stored
```

```test:ash-throttle-no-address
five failures at five usernames with no :remote_ip: a sixth user signs in
```

```test:ash-throttle-success-resets-user
kim's five failures from 192.0.2.9, then her success from another address after the wait: four more failures leave her free; one more failure from 192.0.2.9 then throttles lee from it
```

```test:ash-throttle-empty
five empty usernames from 192.0.2.20: an empty username with no address is :throttled (the shared key), and a real user's right password from 192.0.2.20 is :throttled (the address)
```

```test:ash-throttle-unchecked
a throttled right password emits reason :throttled with strategy and user id nil, adds no token row (a checked one leaves a revoked sign-in token), and is not counted: it signs in once the five failures' wait has passed
```

```test:ash-throttle-timing
a throttled attempt does one hash verification against nothing (simulate/0), as a checked wrong password does one against its hash (valid?/2)
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
