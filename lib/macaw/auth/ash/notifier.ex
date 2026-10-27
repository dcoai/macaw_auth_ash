defmodule Macaw.Auth.Ash.Notifier do
  @moduledoc """
  Tells open pages of a revocation made through Ash, outside `Macaw.Auth`.

  `Macaw.Auth.revoke/2` tells a user's open LiveViews which of their
  sessions ended, and they disconnect at once. But a host on Ash may revoke
  a token without it: AshAuthentication's sign-out revokes by token, an
  admin action may revoke by jti, log-out-everywhere revokes them all.
  Without this notifier those pages would learn only at their next
  re-check (`Macaw.Auth.Live`, every minute by default). The host adds it
  to the token resource, which `Macaw.Auth.Ash.TokenResource` insists on:

      use Ash.Resource, ..., notifiers: [Macaw.Auth.Ash.Notifier]

  On every notification whose record is now a revocation (purpose
  `"revocation"`), it tells the token's user's open pages
  `{:sessions_revoked, [jti]}`: the jti is a `Macaw.Auth.Ash` session's id.
  Revocations made with the `quiet/0` context are not announced. Two
  actions are left to others, so a page is told once: Macaw's own
  revocation (`:macaw_auth_revoke`), which `Macaw.Auth.revoke/2` announces,
  and `revoke_all_stored_for_subject`, a bulk update that sends no
  notifications, which `Macaw.Auth.Ash.AnnounceRevocation` announces.

  **How it tells them:** `Macaw.Auth.announce_revoked/2` (macaw_auth 0.1.1),
  the public way to tell a user's open pages that sessions ended, over
  whichever channel macaw_auth is configured with (a `Registry`, or
  Phoenix.PubSub). It does so only while `Macaw.Auth.Ash` is the configured
  backend; under another backend these tokens are not Macaw sessions.

  Notifications arrive after the transaction commits.
  """

  use Ash.Notifier

  alias Macaw.Auth.Ash.Config

  @impl true
  def notify(%Ash.Notifier.Notification{
        resource: resource,
        action: %{name: action},
        changeset: changeset,
        data: %{purpose: "revocation"} = record
      }) do
    unless action in announced_elsewhere(resource) or quiet?(changeset),
      do: announce(resource, [record])

    :ok
  end

  def notify(_notification), do: :ok

  @doc """
  The context that keeps a revocation unannounced: `Macaw.Auth.Ash`'s
  revocation of the token AshAuthentication's sign-in signs, which was
  never anyone's session.
  """
  @spec quiet() :: map()
  def quiet, do: %{macaw_auth: %{quiet: true}}

  defp quiet?(%{context: %{macaw_auth: %{quiet: true}}}), do: true
  defp quiet?(_changeset), do: false

  defp announced_elsewhere(resource) do
    [
      Macaw.Auth.Ash.TokenResource.revoke_action(),
      AshAuthentication.TokenResource.Info.token_revocation_revoke_all_stored_for_subject_action_name!(
        resource
      )
    ]
  end

  @doc """
  Tells the open pages of each revoked token's user: `records` are token
  rows (`jti`, `subject`). Tokens of another resource's subjects are
  skipped. A no-op unless `Macaw.Auth.Ash` is the configured backend.
  """
  @spec announce(module(), [map()]) :: :ok
  def announce(_resource, records) do
    if Application.get_env(:macaw_auth, :backend) == Macaw.Auth.Ash do
      user_resource = Config.get().user_resource

      records
      |> Enum.group_by(& &1.subject, & &1.jti)
      |> Enum.each(fn {subject, ids} ->
        case Macaw.Auth.Ash.Sessions.subject_user_id(subject, user_resource) do
          {:ok, user_id} -> Macaw.Auth.announce_revoked(user_id, ids)
          :error -> :ok
        end
      end)
    end

    :ok
  end
end
