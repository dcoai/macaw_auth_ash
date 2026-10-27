defmodule Macaw.Auth.Ash.AnnounceRevocation do
  @moduledoc """
  Tells open pages of the tokens an update action revoked:
  `Macaw.Auth.Ash.TokenResource` puts it on AshAuthentication's
  `revoke_all_stored_for_subject`.

  That action is how log-out-everywhere (and a password change with
  `apply_on_password_change?`) revokes a user's tokens: a bulk update run
  without notifications, so `Macaw.Auth.Ash.Notifier` never hears of it.
  This change adds an after-action hook, which Ash runs for a single
  update and for each record of an atomic or streamed bulk one alike, and
  which hands the revoked rows to `Macaw.Auth.Ash.Notifier.announce/2`.

  The hook runs inside the action's transaction, when the data layer has
  one: a page could be told just before the revocation commits. Being told
  early only sends a page to sign in sooner; a revocation that then rolled
  back leaves the session valid, and signing in again recovers it.
  """

  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context), do: hook(changeset)

  @impl true
  def atomic(changeset, _opts, _context), do: {:ok, hook(changeset)}

  defp hook(changeset) do
    Ash.Changeset.after_action(changeset, fn changeset, record ->
      Macaw.Auth.Ash.Notifier.announce(changeset.resource, [record])
      {:ok, record}
    end)
  end
end
