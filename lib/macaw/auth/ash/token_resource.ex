defmodule Macaw.Auth.Ash.TokenResource do
  @moduledoc """
  What `Macaw.Auth.Ash` adds to a host's AshAuthentication token resource:

      defmodule MyApp.Accounts.Token do
        use Ash.Resource,
          domain: MyApp.Accounts,
          data_layer: AshPostgres.DataLayer,
          extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
          notifiers: [Macaw.Auth.Ash.Notifier]
      end

  AshAuthentication's token resource stores a JWT's `jti`, never the JWT,
  with `purpose`, `subject`, `expires_at` and an `extra_data` map. A Macaw
  session is one of those rows (purpose `"user"`), its metadata in
  `extra_data["macaw_auth"]` (`Macaw.Auth.Ash.Sessions`). The resource's
  own actions can store a token, and revoke one by token or jti, but not
  update `extra_data` in place, read rows by subject, or revoke a stored
  row by jti without making it unexpungeable (AshAuthentication's
  `revoke_jti` sets a thousand-year expiry). So this extension adds, unless
  the resource already defines them:

  - `:macaw_auth_read`: a plain read, the primary one when the resource
    has none (log-out-everywhere's bulk update needs one);
  - `:macaw_auth_update`: an update accepting `extra_data` (a session's
    use, its steps);
  - `:macaw_auth_revoke`: an update setting `purpose` to `"revocation"`,
    keeping the row's own expiry, so the expunger still removes it.

  and to AshAuthentication's `revoke_all_stored_for_subject` action the
  `Macaw.Auth.Ash.AnnounceRevocation` change: that action is how
  AshAuthentication's log-out-everywhere revokes, as a bulk update without
  notifications, so a notifier alone would never hear of it.

  A verifier refuses a token resource without `Macaw.Auth.Ash.Notifier`:
  without it, a revocation made through Ash directly would reach open pages
  only at their next re-check.
  """

  use Spark.Dsl.Extension,
    transformers: [Macaw.Auth.Ash.TokenResource.Transformer],
    verifiers: [Macaw.Auth.Ash.TokenResource.Verifier]

  @doc "The read action this extension adds."
  def read_action, do: :macaw_auth_read

  @doc "The update action (`extra_data`) this extension adds."
  def update_action, do: :macaw_auth_update

  @doc "The revoking update action this extension adds."
  def revoke_action, do: :macaw_auth_revoke
end
