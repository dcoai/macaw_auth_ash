defmodule Macaw.Auth.Ash.BackendTest do
  @moduledoc """
  What this backend does beyond the kit: its refusals, its users' fields,
  how its sessions sit in the token resource, and how AshAuthentication
  sees them.
  """

  use ExUnit.Case, async: false

  alias AshAuthentication.{Jwt, TokenResource}
  alias Macaw.Auth
  alias Macaw.Auth.Ash.Config
  alias Macaw.Auth.Ash.Test.{Fixtures, Token, User}

  setup do
    :ok = Fixtures.reset!()
  end

  defp configure(changes) do
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Ash)
    Application.put_env(:macaw_auth, Macaw.Auth.Ash, Keyword.merge(previous, changes))
    on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Ash, previous) end)
  end

  describe "authenticate" do
    test "a user's fields: username, display name, roles, source, no second factor" do
      {_user, creds} = Fixtures.user!(%{roles: ["admin", "viewer"], display_name: "Ada"})

      assert {:ok, user} = Auth.authenticate(creds)

      assert %Auth.User{
               username: username,
               display_name: "Ada",
               roles: ["admin", "viewer"],
               source: "local",
               disabled: false,
               second_factor: :none
             } = user

      assert username == creds.username
    end

    test "roles from a function of the record" do
      configure(roles_from: {__MODULE__, :shouted})
      {_user, creds} = Fixtures.user!(%{roles: ["viewer"]})
      assert {:ok, %{roles: ["VIEWER"]}} = Auth.authenticate(creds)
    end

    test "a disabled user is refused as disabled only with the right password" do
      {user, creds} = Fixtures.user!(%{})
      :ok = Fixtures.disable!(user)

      assert Auth.authenticate(creds) == {:error, :disabled}

      assert Auth.authenticate(%{creds | password: creds.password <> "x"}) ==
               {:error, :invalid_credentials}
    end

    test "an empty or missing username or password is the same refusal" do
      {_user, creds} = Fixtures.user!(%{})

      for bad <- [%{creds | password: ""}, %{creds | username: ""}, %{}, %{username: 1}] do
        assert Auth.authenticate(bad) == {:error, :invalid_credentials}
      end
    end

    # The password is the strategy's: AshAuthentication's arguments are
    # Ash strings, trimmed at registration and sign-in alike.
    test "the username is trimmed; the password is checked as AshAuthentication checks it" do
      {_user, creds} = Fixtures.user!(%{})
      assert {:ok, _} = Auth.authenticate(%{creds | username: " #{creds.username} "})
      assert {:ok, _} = Auth.authenticate(%{creds | password: " #{creds.password} "})

      assert Auth.authenticate(%{creds | password: String.upcase(creds.password)}) ==
               {:error, :invalid_credentials}
    end

    test "an unknown user and a wrong password each cost one hash" do
      {_user, creds} = Fixtures.user!(%{})
      wrong = %{creds | password: "wrong"}
      unknown = %{creds | username: "nobody"}

      {wrong_us, _} = :timer.tc(fn -> for _ <- 1..5, do: Auth.authenticate(wrong) end)
      {unknown_us, _} = :timer.tc(fn -> for _ <- 1..5, do: Auth.authenticate(unknown) end)

      # Same order of time: a skipped hash would be far quicker.
      assert unknown_us > wrong_us / 4
    end
  end

  def shouted(record), do: Enum.map(record.roles, &String.upcase/1)

  describe "sessions in the token resource" do
    test "a session is a stored user token: the jti, never the JWT" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user, user_agent: "Test/1.0")

      assert {:ok, %{"jti" => jti, "sub" => sub, "purpose" => "user"}} = Jwt.peek(token)
      assert jti == session.id
      assert sub == "user?id=#{user.id}"

      [row] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false)
      assert {row.jti, row.purpose, row.subject} == {jti, "user", sub}
      assert row.extra_data["macaw_auth"]["user_agent"] == "Test/1.0"
    end

    test "AshAuthentication accepts a live session's token and refuses a revoked one" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)

      assert {:ok, _claims, User} = Jwt.verify(token, User)
      refute TokenResource.jti_revoked?(Token, session.id)

      :ok = Auth.revoke(session.id)

      assert TokenResource.jti_revoked?(Token, session.id)
      assert Jwt.verify(token, User) == :error
    end

    test "a token AshAuthentication signed for itself is not a Macaw session" do
      {user, _} = Fixtures.user!(%{})
      record = Ash.get!(User, user.id, authorize?: false)
      {:ok, token, _claims} = Jwt.token_for_user(record, %{"purpose" => "user"})

      assert Auth.fetch(token) == {:error, :invalid}
      assert Auth.list_sessions(user.id) == []
    end

    test "a request records use at most hourly; a re-check never does" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      later = DateTime.add(session.last_used_at, 2 * 3_600, :second)

      {:ok, _, rechecked} = Auth.fetch(token, touch: false, now: later)
      assert rechecked.last_used_at == session.last_used_at

      {:ok, _, touched} = Auth.fetch(token, touch: true, now: later)
      assert touched.last_used_at == later
      {:ok, _, stored} = Auth.fetch_by_id(session.id)
      assert stored.last_used_at == later

      soon = DateTime.add(later, 60, :second)
      {:ok, _, again} = Auth.fetch(token, touch: true, now: soon)
      assert again.last_used_at == later
    end

    test "a step completed is recorded on the session" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user, second_factor_passed: false)
      refute session.second_factor_passed

      :ok = Auth.complete_step(session.id, :password_change)
      :ok = Auth.complete_step(session.id, :second_factor)

      {:ok, _, session} = Auth.fetch(token)
      assert session.completed_steps == [:password_change]
      assert session.second_factor_passed
    end

    test "an expired or disabled session is revoked at its look-up" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      past = DateTime.add(DateTime.utc_now(), 15 * 86_400, :second)

      assert Auth.fetch(token, now: past) == {:error, :expired}
      assert TokenResource.jti_revoked?(Token, session.id)
      assert Auth.fetch(token) == {:error, :invalid}
    end

    test "the second factor is unsupported" do
      {user, _} = Fixtures.user!(%{})
      {:ok, _, session} = Auth.create_session(user)
      assert Auth.verify_second_factor(session.id, "123456") == {:error, :unsupported}
    end

    test "ids and tokens of the wrong shape are invalid, never a crash" do
      for bad <- ["", "a.b", "a.b.c", "not a jwt at all", <<255, 0, 1>>] do
        assert Auth.fetch(bad) == {:error, :invalid}
      end

      assert Auth.fetch_by_id(123) == {:error, :invalid}
      assert Auth.fetch_by_id("no-such-jti") == {:error, :invalid}
      assert Auth.revoke("no-such-jti") == :ok
    end
  end

  describe "configuration" do
    test "a fault names its key" do
      assert_raise ArgumentError, ~r/strategy :nope is not on/, fn ->
        Config.parse!(user_resource: User, strategies: [:nope])
      end

      assert_raise ArgumentError, ~r/unknown keys \[:color_scheme\]/, fn ->
        Config.parse!(user_resource: User, color_scheme: :dark)
      end

      assert_raise ArgumentError, ~r/disabled_field: :nope is not an attribute/, fn ->
        Config.parse!(user_resource: User, disabled_field: :nope)
      end

      assert_raise ArgumentError, ~r/idle_days/, fn ->
        Config.parse!(user_resource: User, idle_days: 0)
      end
    end

    test "the token resource and domain default to the user resource's" do
      config = Config.parse!(user_resource: User)
      assert {config.token_resource, config.domain} == {Token, Macaw.Auth.Ash.Test.Accounts}
      assert config.username_field == :username
    end
  end
end
