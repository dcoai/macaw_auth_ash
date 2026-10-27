# 02 — Sessions {#ash-sessions}

`Macaw.Auth.Ash.Sessions` keeps `Macaw.Auth.Ash`'s sessions in the host's AshAuthentication token resource: `create/2`, `fetch/2`, `fetch_by_id/2`, `list/2`, `revoke/2` and `complete_step/3`, the contract's session callbacks ([macaw_auth 01 §2](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-backend)). **Every function honors `:now`** (a `DateTime`).

## 1. A session is a stored user token {#ash-sessions-token}

`Macaw.Auth.Ash.Sessions.create/2` loads the user's record, signs **an ordinary AshAuthentication user JWT** for it (`AshAuthentication.Jwt.token_for_user/2`, purpose `"user"`: the resource's own signing secret, lifetime and claims), and stores its row in the token resource (`store_token`, purpose `"user"`):
- **the session's id is the token's `jti`;** the row's `subject` is the user's (`"<subject name>?<primary key>=<id>"`), its `expires_at` the JWT's;
- **Macaw's metadata is in the row's `extra_data["macaw_auth"]`:** `created_at` and `last_used_at` (ISO 8601), `remote_ip` (a string; a tuple formatted as one), `user_agent` (truncated to 255 characters), `second_factor_passed` (the option, default true) and `completed_steps` (`[]`);
- **the JWT goes to the client** as the session's token. A resource that stores every token itself (`store_all_tokens?`) gets the same row, with Macaw's metadata added by the upsert.

**Why the token resource, not a session table of its own:** it is where an Ash host already keeps tokens, so **one revocation means the same to AshAuthentication's plugs and to Macaw** (a revoked session is a token AshAuthentication refuses too, and a token AshAuthentication revokes is a session Macaw refuses), its expunger clears the rows, and the host has no second table to migrate. What the resource lacked, an update of `extra_data` and a revocation by jti that keeps the row's expiry, `Macaw.Auth.Ash.TokenResource` adds ([03](03-token-resource.md)).

**No token is stored.** The row holds the `jti`, a random value inside the JWT's signed payload, never the JWT; a `jti` alone signs nobody in, since a token must carry the resource's signature.

```test:ash-session-row
a session's token is a JWT whose jti is the session's id, sub "user?id=<id>" and purpose "user"; the resource holds one row with that jti, purpose and subject, and extra_data["macaw_auth"]["user_agent"] "Test/1.0"
```

```test:ash-session-not-stored
the kit's "no session token is stored as it is" holds over every column of every token row, read with plain SQL
```

## 2. Looking a session up {#ash-sessions-fetch}

`Macaw.Auth.Ash.Sessions.fetch/2` takes a token:
1. **it must look like a JWT:** valid UTF-8 and three base64url segments; anything else is `:invalid` before it reaches the JWT library;
2. **its signature and claims are verified** against the user resource (`AshAuthentication.Jwt.verify/2`), which also refuses a revoked token;
3. **its row** must be the jti's, with purpose `"user"` **and Macaw's metadata:** a token AshAuthentication minted for itself is not a Macaw session (`:invalid`), and lists nowhere;
4. **the row's subject must be the token's,** so a row can only ever stand for the token that made it;
5. then the session is validated (§3).

`Macaw.Auth.Ash.Sessions.fetch_by_id/2` finds the row by its jti (a binary; anything else is `:invalid`) and validates it with the row's own subject. Either way, the user is loaded from the subject (gone, `:invalid`) and reported as it is now.

```test:ash-session-wrong-shape
fetch of "", "a.b", "a.b.c", "not a jwt at all" and <<255, 0, 1>> are {:error, :invalid}; fetch_by_id(123) and fetch_by_id("no-such-jti") are {:error, :invalid}; revoke("no-such-jti") is :ok
```

```test:ash-session-foreign-token
a user JWT AshAuthentication signed for itself fetches as {:error, :invalid}, and the user lists no sessions
```

## 3. Idle expiry and the JWT's lifetime {#ash-sessions-idle}

Validating, in order:
- **a disabled user's session is revoked** (its row flipped, §5) and refused, `:disabled`;
- **an idle session** (unused more than `idle_days` × 86 400 seconds) **or one past its row's `expires_at`** is revoked and refused, `:expired`;
- **`touch: true`** (a request) records use **at most once an hour** (when `last_used_at` is at least 3 600 seconds old), by updating the row's `extra_data` while it is still a live session (a revocation racing the write wins); **`touch: false`** (a re-check, and the default) **never does,** so an idle tab never keeps a session alive.

**The JWT's own expiry is the session's absolute limit:** the user resource's `token_lifetime`. **A host sets it to at least `idle_days`,** or sessions end before they are idle. The rule is documented, not checked ([06 §2](06-limits.md#ash-gaps)).

Expired and disabled sessions are not announced to open pages; they find them gone at their next re-check, as under the native backend.

```test:ash-session-touch
two hours after creation, a re-check (touch: false) leaves last_used_at; a request (touch: true) sets it, and fetch_by_id reads it back; a request a minute later leaves it
```

```test:ash-session-expired
a session looked up 15 days on (idle_days 14) is {:error, :expired}, its jti revoked to AshAuthentication, and its token then :invalid
```

## 4. Steps {#ash-sessions-steps}

`Macaw.Auth.Ash.Sessions.complete_step/3` updates the row's metadata: `:second_factor` and `:second_factor_enroll` set `second_factor_passed`; any other step's name joins `completed_steps`, once. A session that isn't there is left alone, `:ok`. **Steps come back as atoms only by lookup** among `Macaw.Auth.steps/0`.

```test:ash-session-steps
a session made with second_factor_passed false, after :password_change and :second_factor, reads completed_steps [:password_change] and second_factor_passed true
```

## 5. Revocation, both ways {#ash-sessions-revoke}

**Revoking flips the row's purpose to `"revocation"`** (the extension's `:macaw_auth_revoke`, [03](03-token-resource.md)), the state AshAuthentication's own revocation check looks for, **keeping the row's expiry,** so the expunger removes it when the JWT could no longer verify anyway. Only live rows (purpose `"user"`) are flipped, in one bulk update that returns them, so a row revoked twice at once is counted by one of the two.
- `revoke(id)`: `{user_id, [id]}` (the user id from the row's subject; nil for another resource's subject), or `{nil, []}` when there is no live session by that id, or the id isn't a binary;
- `revoke({:user, user_id}, except: id)`: every live session of the user's but `except`: `{user_id, ids}`, the ids empty when there were none;
- `list(user_id)`: the user's live sessions, **newest first,** by `created_at` and then id. The rows are found by the subject made from the id alone, so a deleted user's sessions can still be found.

`Macaw.Auth.revoke/2` then announces the ids ([macaw_auth 01 §6](https://gitlab.conet.yarina.org/dco-tek/macaw_auth/-/blob/main/spec/01-contract.md#auth-revocation)); this bulk update sends no notifications, so the notifier never announces it twice ([04](04-notifier.md)).

**Both ways:** a session Macaw revokes is a token AshAuthentication refuses (`jti_revoked?`, `Jwt.verify/2` fails); and a token AshAuthentication revokes (its sign-out by token, a revoke by jti, log-out-everywhere) is a session Macaw refuses, whose open pages are told ([04](04-notifier.md)).

`Macaw.Auth.Ash.Sessions.subject_user_id/2` gives the user id a subject names (`{:ok, id}`), or `:error` for another resource's subject.

```test:ash-revoke-both-ways
a live session's token verifies with AshAuthentication and its jti isn't revoked; after Macaw.Auth.revoke(session.id), jti_revoked? is true and Jwt.verify is :error
```

```test:ash-revoked-by-ash
TokenResource.revoke(Token, token) makes the session's token and id :invalid to Macaw
```
