# 05 — The LDAP strategy {#ash-ldap}

`Macaw.Auth.Ash.Strategy.Ldap` is a directory sign-in as an AshAuthentication custom strategy: macaw_auth's `Macaw.Auth.Native.Source.Ldap` ([macaw_auth 07](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/07-native-ldap.md#auth-ldap): its RFC 4514 and filter escaping, its TLS rules with `allow_plaintext: false`, its group checks and role mapping) on an Ash user resource, which it provisions at a user's first sign-in. AshAuthentication has no LDAP strategy; this is the one implementation, used from Ash.

## 1. The DSL {#ash-ldap-dsl}

The user resource takes the extension, and names the strategy among its `strategies`:

```elixir
use Ash.Resource, extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap], ...

authentication do
  strategies do
    ldap :nas do
      source {MyApp.Directory, :nas, []}
      identity_field :username
      roles_field :roles
      source_field :source
      display_name_field :display_name
      disabled_field :disabled_at
    end
  end
end
```

| Option | What | Default |
|---|---|---|
| name (the argument) | the strategy's name, and the source's | `:ldap` |
| `source` (required) | the directory's configuration, as a native LDAP source's ([macaw_auth 07 §1](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/07-native-ldap.md#auth-ldap-config)): a map, or `{module, function, args}` returning one | |
| `identity_field` | the attribute the directory's username goes in | `:username` |
| `roles_field` | the attribute (a list of strings) of roles | `:roles` |
| `source_field` | the attribute naming which source owns the row | `:source` |
| `display_name_field` | the attribute for the directory's display name | none |
| `disabled_field` | a boolean or timestamp attribute: set means refused | none |
| `sign_in_action_name` | | `sign_in_with_<name>` |
| `provision_action_name` | | `provision_with_<name>` |
| `refresh_action_name` | | `refresh_with_<name>` |

The strategy is the struct `%Macaw.Auth.Ash.Strategy.Ldap{}` with these fields, plus the `resource` and `strategy_module` AshAuthentication fills. **Every named field must be an attribute of the resource:** otherwise a DSL error at compile time, at `[:authentication, :strategies, <name>, <option>]`, `"<field> is not an attribute of this resource"`.

**The source is read at each sign-in** (`Macaw.Auth.Ash.Strategy.Ldap.source!/1`): the map, or the function's result, with `type: :ldap` and `name` defaulting to the strategy's name, parsed as a native source. **Prefer the function:** a map in the resource is fixed when it compiles, and a host's directory and its service password belong to the runtime (`bind_password: {:env, "VAR"}` is resolved at sign-in either way). **A configuration fault raises `ArgumentError` at sign-in,** `"LDAP strategy <name>: <fault>"`: a deployment bug, not a refusal.

```test:ash-ldap-fields
a strategy naming an identity, roles, source, display name or disabled field that isn't an attribute of the resource fails to compile with a DslError at [:authentication, :strategies, <name>, <option>], "<field> is not an attribute of this resource"
```

```test:ash-ldap-plaintext
a strategy whose source has starttls: false and no allow_plaintext raises ArgumentError matching "allow_plaintext" at sign_in/4
```

## 2. The actions it builds {#ash-ldap-actions}

Unless the resource defines them already:
- **`sign_in_with_<name>`:** a generic action taking `username` (a string) and `password` (a sensitive string), returning the user record (`Macaw.Auth.Ash.Strategy.Ldap.SignIn`). Through AshAuthentication (its plug, or `AshAuthentication.Strategy.action/4`) **it signs a user token as the password strategy does,** in the record's `:token` metadata, when the resource has tokens (unless the action's context sets `token_type` to anything but `:user`). **Every refusal is the same `AshAuthentication.Errors.AuthenticationFailed`,** so neither AshAuthentication's plug nor an API built on the action tells a wrong password from an unknown user; the reason and its explanation are in its `caused_by`, for logs;
- **`provision_with_<name>`:** a create accepting the identity, roles and source fields, and the display name's;
- **`refresh_with_<name>`:** an update accepting the roles and the display name's.

The strategy is registered for AshAuthentication's plug and router (`AshAuthentication.Strategy` protocol): **one phase, sign-in,** `POST /<subject>/<name>` (the user's subject name), the params under the subject's key (`username`, `password`), as the password strategy's sign-in is. It doesn't require tokens.

`Macaw.Auth.Ash` doesn't go through the action: it calls `sign_in/4` itself (§3) and makes its own session, so a directory sign-in through Macaw signs no extra token.

```test:ash-ldap-action
AshAuthentication.Strategy.action(nas, :sign_in, %{"username" => "bob", "password" => "bob-password"}) gives bob's record with a token that verifies; a wrong password is an error holding AuthenticationFailed; routes are [{"/user/nas", :sign_in}]
```

## 3. Signing in {#ash-ldap-sign-in}

`Macaw.Auth.Ash.Strategy.Ldap.sign_in/4` (`strategy`, `username`, `password`, `opts`) checks the password against the directory ([macaw_auth 07 §3](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/07-native-ldap.md#auth-ldap-flow)) and provisions the user (§4): `{:ok, record}`, or `{:error, reason, knows?}`:
- a directory refusal gives the source's reason, and **`knows?` is the source's own `knows?/2`** ([macaw_auth 07 §6](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/07-native-ldap.md#auth-ldap-knows)), so `Macaw.Auth.Ash`'s chain passes an unreachable directory, an unknown entry or a direct-bind wrong password on to the next strategy ([01 §2](01-backend.md#ash-authenticate));
- **a provisioning refusal is always final:** `:username_taken` or `:disabled`.

`Macaw.Auth.Ash.Strategy.Ldap.explain_refusal/1` explains a reason, for logs: `:username_taken` is `"a user with that username belongs to another source"`, `:disabled` is `"the user is disabled"`, and every other is the source's explanation.

```test:ash-ldap-reasons
sign_in/4 for alice with a wrong password is {:error, :invalid_credentials, false}; carol is {:error, :not_in_group, true}; an empty password is {:error, :empty_password, false}
```

```test:ash-ldap-refusals
through Macaw.Auth.authenticate, a wrong password, an unknown user, carol outside the required group and "alice,cn=users" are each :invalid_credentials, and no row for carol is made
```

```test:ash-ldap-tls
without the directory's CA, sign_in/4 is {:error, :tls_failed, false}
```

## 4. Provisioning {#ash-ldap-provision}

As `Macaw.Auth.Native.Provision` ([macaw_auth 06 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/06-native-sources.md#auth-provision)), over the resource, by the identity field:
- **first sign-in:** the provision action makes a row with the directory's (normalized) username, its roles, `source_field` the directory's name, the display name when there is a field for it, and **no password;**
- **every later sign-in:** the refresh action replaces the row's roles and display name with the directory's, so a user removed from an admin group loses the role at their next sign-in;
- **a row with that username that another source owns** (a local user, or another directory's) **is never taken over:** `:username_taken`;
- **a disabled row stays refused,** `:disabled`, left as it is;
- **two first sign-ins at once:** the resource needs **a unique identity on `identity_field`**, so the second create fails; it looks again, once, and uses the row the other made. Any other create failure is a bug in the resource, and raises.

**What the directory says beyond these is not stored:** its DN, the entry's id, the email, the group DNs (the native source's `extra`). A user resource has no standard place for them.

```test:ash-ldap-provision-first
alice's first sign-in through Macaw.Auth makes her row with source "nas", roles ["admin"] and display name "Alice Admin", and the user's id is the row's; bob signs in with ["viewer"]
```

```test:ash-ldap-refresh
roles refreshed to ["owner"] by hand are ["admin"] again at alice's next sign-in, on the same row
```

```test:ash-ldap-no-takeover
a local bob is never signed in by the directory's bob; a row "alice" owned by source "other" is refused, and keeps its source and roles
```

```test:ash-ldap-disabled
a disabled provisioned alice is :disabled with the right password and :invalid_credentials with a wrong one
```

```test:ash-ldap-session
a directory user's session resolves to them, with source "nas"
```
