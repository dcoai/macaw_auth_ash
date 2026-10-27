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
  alias Macaw.Auth.Ash.{AnnounceRevocation, Notifier}
  alias Macaw.Auth.Ash.Test.{Fixtures, Token, User}

  setup do
    :ok = Fixtures.reset!()
    {user, creds} = Fixtures.user!(%{})
    %{user: user, creds: creds}
  end

  @tag verifies: "ash-notify-by-token"
  test "revoking a session's token through AshAuthentication tells its open pages", %{user: user} do
    {:ok, token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = TokenResource.revoke(Token, token)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
    assert Auth.fetch(token) == {:error, :invalid}
    assert Auth.fetch_by_id(session.id) == {:error, :invalid}
  end

  @tag verifies: "ash-notify-by-jti"
  test "revoking by jti through AshAuthentication tells them too", %{user: user} do
    {:ok, _token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)
    subject = "user?id=#{user.id}"

    :ok = TokenResource.Actions.revoke_jti(Token, session.id, subject)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
  end

  @tag verifies: "ash-notify-log-out-everywhere"
  test "log-out-everywhere tells every open page", %{user: user} do
    {:ok, _, first} = Auth.create_session(user)
    {:ok, _, second} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    log_out_everywhere(user)

    # One message per session, each naming it alone.
    assert_receive {:sessions_revoked, [a]}
    assert_receive {:sessions_revoked, [b]}
    refute_receive {:sessions_revoked, _}
    assert Enum.sort([a, b]) == Enum.sort([first.id, second.id])
    assert Auth.list_sessions(user.id) == []
  end

  @tag verifies: "ash-notify-own-once"
  test "Macaw's own revocation is told once", %{user: user} do
    {:ok, _, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = Auth.revoke(session.id)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
    refute_receive {:sessions_revoked, _}
  end

  @tag verifies: "ash-authenticate-discarded-token"
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

  @tag verifies: "ash-notify-other-backend"
  test "under another backend, nothing is told", %{user: user} do
    {:ok, token, _session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)
    Application.put_env(:macaw_auth, :backend, Macaw.Auth.Native)
    on_exit(fn -> Application.put_env(:macaw_auth, :backend, Macaw.Auth.Ash) end)

    :ok = TokenResource.revoke(Token, token)
    refute_receive {:sessions_revoked, _}
  end

  @tag verifies: "ash-notify-quiet"
  test "a password sign-in's discarded token is announced to nobody", %{
    user: user,
    creds: creds
  } do
    :ok = Auth.subscribe(user.id)
    {:ok, _} = Auth.authenticate(creds)
    refute_receive {:sessions_revoked, _}
  end

  # The chapter's promise: whoever revokes, the user's open pages hear of
  # each session once.
  @tag verifies: "ash-announce"
  test "every revocation, whoever makes it, reaches the open pages once", %{user: user} do
    {:ok, by_token, by_token_session} = Auth.create_session(user)
    {:ok, _, by_jti} = Auth.create_session(user)
    {:ok, _, by_macaw} = Auth.create_session(user)
    {:ok, _, by_all} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = TokenResource.revoke(Token, by_token)
    :ok = TokenResource.Actions.revoke_jti(Token, by_jti.id, "user?id=#{user.id}")
    :ok = Auth.revoke(by_macaw.id)
    log_out_everywhere(user)

    heard =
      for _ <- 1..4 do
        assert_receive {:sessions_revoked, [id]}
        id
      end

    refute_receive {:sessions_revoked, _}
    assert Enum.sort(heard) == Enum.sort([by_token_session.id, by_jti.id, by_macaw.id, by_all.id])
  end

  @tag verifies: "ash-notifier"
  test "the notifier tells after commit, and only of a revocation it alone would announce", %{
    user: user
  } do
    {:ok, token, session} = Auth.create_session(user)
    {:ok, quiet_token, _} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    # A notification that isn't a revocation (a session's use recorded).
    later = DateTime.add(session.last_used_at, 2 * 3_600, :second)
    {:ok, _, _} = Auth.fetch(token, touch: true, now: later)
    refute_receive {:sessions_revoked, _}

    # A revocation made with the quiet context.
    assert Notifier.quiet() == %{macaw_auth: %{quiet: true}}
    :ok = TokenResource.Actions.revoke(Token, quiet_token, context: Notifier.quiet())
    refute_receive {:sessions_revoked, _}

    # Ash delivers the notification once the transaction commits.
    {:ok, :revoked} =
      Ash.transact(Token, fn ->
        :ok = TokenResource.revoke(Token, token)
        refute_receive {:sessions_revoked, _}
        :revoked
      end)

    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
  end

  @tag verifies: "ash-announce-revocation"
  test "the bulk revocation is announced from its after-action hook, inside the transaction", %{
    user: user
  } do
    {:ok, _, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    revoke_all =
      TokenResource.Info.token_revocation_revoke_all_stored_for_subject_action_name!(Token)

    action = Ash.Resource.Info.action(Token, revoke_all)
    assert Enum.any?(action.changes, &match?(%{change: {AnnounceRevocation, _}}, &1))

    Code.ensure_loaded!(AnnounceRevocation)
    assert function_exported?(AnnounceRevocation, :change, 3)
    assert function_exported?(AnnounceRevocation, :atomic, 3)

    # Told before the transaction ends.
    {:ok, :done} =
      Ash.transact(Token, fn ->
        log_out_everywhere(user)
        assert_received {:sessions_revoked, [id]}
        assert id == session.id
        :done
      end)

    refute_receive {:sessions_revoked, _}
  end

  @tag verifies: "ash-announce-call"
  test "announce/2 tells each subject's user of its jtis, skipping other resources' subjects", %{
    user: user
  } do
    {other, _} = Fixtures.user!(%{})
    :ok = Auth.subscribe(user.id)
    :ok = Auth.subscribe(other.id)

    rows = [
      %{subject: "user?id=#{user.id}", jti: "a"},
      %{subject: "other_thing?id=#{other.id}", jti: "x"},
      %{subject: "user?id=#{user.id}", jti: "b"},
      %{subject: "user?id=#{other.id}", jti: "c"}
    ]

    assert Notifier.announce(Token, rows) == :ok

    assert_receive {:sessions_revoked, ["a", "b"]}
    assert_receive {:sessions_revoked, ["c"]}
    refute_receive {:sessions_revoked, _}

    # The hidden channel is gone: a {:announce, …} revocation revokes nothing.
    assert Macaw.Auth.Ash.revoke_sessions({:announce, user.id, ["a"]}, []) == {nil, []}
  end

  defp log_out_everywhere(user) do
    {:ok, strategy} = AshAuthentication.Info.strategy(User, :log_out_everywhere)
    record = Ash.get!(User, user.id, authorize?: false)
    :ok = AshAuthentication.Strategy.action(strategy, :log_out_everywhere, %{user: record})
  end
end
