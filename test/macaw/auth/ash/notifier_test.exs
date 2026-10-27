defmodule Macaw.Auth.Ash.NotifierTest do
  @moduledoc """
  A revocation made through Ash, outside `Macaw.Auth`, reaches the user's
  open pages: by token (AshAuthentication's sign-out), by jti, and by
  log-out-everywhere (a bulk update without notifications, announced by
  `Macaw.Auth.Ash.AnnounceRevocation`). Macaw's own revocation, and the
  token the password sign-in signs and Macaw revokes at once, are told
  once and not at all.
  """

  use ExUnit.Case, async: false

  alias AshAuthentication.TokenResource
  alias Macaw.Auth
  alias Macaw.Auth.Ash.Test.{Fixtures, Token, User}

  setup do
    :ok = Fixtures.reset!()
    {user, creds} = Fixtures.user!(%{})
    %{user: user, creds: creds}
  end

  test "revoking a session's token through AshAuthentication tells its open pages", %{user: user} do
    {:ok, token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = TokenResource.revoke(Token, token)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
    assert Auth.fetch(token) == {:error, :invalid}
    assert Auth.fetch_by_id(session.id) == {:error, :invalid}
  end

  test "revoking by jti through AshAuthentication tells them too", %{user: user} do
    {:ok, _token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)
    subject = "user?id=#{user.id}"

    :ok = TokenResource.Actions.revoke_jti(Token, session.id, subject)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
  end

  test "log-out-everywhere tells every open page", %{user: user} do
    {:ok, _, first} = Auth.create_session(user)
    {:ok, _, second} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    {:ok, strategy} = AshAuthentication.Info.strategy(User, :log_out_everywhere)
    record = Ash.get!(User, user.id, authorize?: false)
    :ok = AshAuthentication.Strategy.action(strategy, :log_out_everywhere, %{user: record})

    ids = receive_ids([])
    assert first.id in ids and second.id in ids
    assert Auth.list_sessions(user.id) == []
  end

  test "Macaw's own revocation is told once", %{user: user} do
    {:ok, _, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = Auth.revoke(session.id)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
    refute_receive {:sessions_revoked, _}
  end

  test "the token the password sign-in signs is revoked at once, untold", %{
    user: user,
    creds: creds
  } do
    :ok = Auth.subscribe(user.id)
    {:ok, _} = Auth.authenticate(creds)
    refute_receive {:sessions_revoked, _}

    purposes =
      Token
      |> Ash.read!(action: :macaw_auth_read, authorize?: false)
      |> Enum.map(& &1.purpose)

    assert purposes == ["revocation"]
    assert Auth.list_sessions(user.id) == []
  end

  test "under another backend, nothing is told", %{user: user} do
    {:ok, token, _session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)
    Application.put_env(:macaw_auth, :backend, Macaw.Auth.Native)
    on_exit(fn -> Application.put_env(:macaw_auth, :backend, Macaw.Auth.Ash) end)

    :ok = TokenResource.revoke(Token, token)
    refute_receive {:sessions_revoked, _}
  end

  # Log-out-everywhere tells each page in its own message.
  defp receive_ids(acc) do
    receive do
      {:sessions_revoked, ids} -> receive_ids(acc ++ ids)
    after
      100 -> acc
    end
  end
end
