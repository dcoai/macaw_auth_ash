# 04 — Announcing revocations {#ash-announce}

`Macaw.Auth.revoke/2` tells a user's open LiveViews which of their sessions ended, and they disconnect at once ([macaw_auth 01 §6](https://github.com/dcoai/macaw_auth/blob/main/spec/01-contract.md#auth-revocation)). But an Ash host may revoke a token without it: AshAuthentication's sign-out revokes by token, an admin action may revoke by jti, log-out-everywhere revokes them all. Without what follows, those pages would learn only at their next re-check (every minute by default). **Every revocation, whoever makes it, reaches the user's open pages once.**

## 1. The notifier {#ash-notifier}

`Macaw.Auth.Ash.Notifier`, an Ash notifier on the token resource (required, [03 §2](03-token-resource.md#ash-token-verifier)). **Ash delivers its notifications after the transaction commits.** On every notification whose record is now a revocation (purpose `"revocation"`), it announces the token's jti to its user's open pages (§3), **except:**
- **Macaw's own revocation** (`:macaw_auth_revoke`), which `Macaw.Auth.revoke/2` announces;
- **`revoke_all_stored_for_subject`,** a bulk update that sends no notifications, which `Macaw.Auth.Ash.AnnounceRevocation` announces (§2);
- **a revocation made with the `quiet/0` context:** `Macaw.Auth.Ash.Notifier.quiet/0` is `%{macaw_auth: %{quiet: true}}`, which `Macaw.Auth.Ash` sets on its revocation of the token AshAuthentication's sign-in signs, which was never anyone's session ([01 §2](01-backend.md#ash-authenticate)).

Every other notification is ignored.

```test:ash-notify-by-token
a subscriber of the user hears {:sessions_revoked, [session.id]} when TokenResource.revoke(Token, token) revokes the session's token
```

```test:ash-notify-by-jti
a subscriber hears {:sessions_revoked, [session.id]} when TokenResource.Actions.revoke_jti/3 revokes the session's jti
```

```test:ash-notify-own-once
Macaw.Auth.revoke(session.id) is heard exactly once
```

```test:ash-notify-quiet
a password sign-in's discarded token is announced to nobody
```

## 2. Announcing a bulk revocation {#ash-announce-revocation}

`Macaw.Auth.Ash.AnnounceRevocation` is an Ash change that `Macaw.Auth.Ash.TokenResource` puts on `revoke_all_stored_for_subject` ([03 §1](03-token-resource.md#ash-token-actions)), the action log-out-everywhere (and a password change with `apply_on_password_change?`) revokes through. It adds an after-action hook, which Ash runs for a single update and for each record of an atomic or streamed bulk one alike (it implements both `change/3` and `atomic/3`), and which hands each revoked row to the announcement (§3).

**The hook runs inside the action's transaction,** when the data layer has one: a page could be told just before the revocation commits. Being told early only sends a page to sign in sooner; a revocation that then rolled back leaves the session valid, and signing in again recovers it. This is the one place a revocation is announced before commit; the notifier's are after it (§1).

```test:ash-notify-log-out-everywhere
log-out-everywhere of a user with two sessions tells a subscriber both ids (one message each), and the user has no sessions left
```

## 3. The announcement {#ash-announce-call}

`Macaw.Auth.Ash.Notifier.announce/2` (`resource`, `records`) groups token rows by subject, turns each subject into its user's id (`Macaw.Auth.Ash.Sessions.subject_user_id/2`; another resource's subjects are skipped), and calls **`Macaw.Auth.announce_revoked(user_id, jtis)`**: macaw_auth's public way to tell a user's open pages that sessions ended, over whichever channel macaw_auth is configured with (a `Registry`, or Phoenix.PubSub). `:ok`.

**It announces only while `Macaw.Auth.Ash` is the configured backend:** under another backend these tokens are not Macaw sessions.

**The public call replaced a hidden channel.** The first version reached macaw_auth's private broadcast through `Macaw.Auth.revoke({:announce, user_id, ids})`, which this backend handed back unrevoked. That was fixed at the source on review: macaw_auth 0.1.1 added `announce_revoked/2`, this library depends on 0.1.1 and calls it, and the `{:announce, …}` clause is gone (macaw_compose#53).

```test:ash-notify-other-backend
with the backend switched to Macaw.Auth.Native, revoking a session's token through AshAuthentication tells nobody
```
