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

  # The throttle is macaw_auth's native one (`Macaw.Auth.Native.Throttle`):
  # its backoff and sweep are tested there; here, that this backend counts
  # and honors it as the native backend does.
  describe "throttle" do
    @t0 ~U[2026-01-01 00:00:00.000Z]

    defp at(ms), do: DateTime.add(@t0, ms, :millisecond)

    defp fail_times(creds, n, opts) do
      for _ <- 1..n do
        assert Auth.authenticate(%{creds | password: "wrong"}, opts) ==
                 {:error, :invalid_credentials}
      end
    end

    test "five failures back off: the right password is throttled until the wait has passed" do
      {_user, creds} = Fixtures.user!(%{})
      fail_times(creds, 5, remote_ip: "192.0.2.1", now: @t0)

      assert Auth.authenticate(creds, remote_ip: "192.0.2.1", now: @t0) == {:error, :throttled}

      assert Auth.authenticate(creds, remote_ip: "192.0.2.1", now: at(999)) ==
               {:error, :throttled}

      assert {:ok, _} = Auth.authenticate(creds, remote_ip: "192.0.2.1", now: at(1_000))
    end

    test "per address: failures at five unknown usernames throttle a sixth from that address" do
      {_user, creds} = Fixtures.user!(%{})

      for n <- 1..5 do
        assert Auth.authenticate(%{username: "nobody#{n}", password: "x"},
                 remote_ip: "198.51.100.1",
                 now: @t0
               ) == {:error, :invalid_credentials}
      end

      assert Auth.authenticate(creds, remote_ip: "198.51.100.1", now: @t0) == {:error, :throttled}
      assert {:ok, _} = Auth.authenticate(creds, remote_ip: "198.51.100.2", now: @t0)
    end

    test "per username: failures from five addresses throttle a sixth; another user signs in" do
      {_user, ned} = Fixtures.user!(%{})
      {_user, oli} = Fixtures.user!(%{})

      for n <- 1..5, do: fail_times(ned, 1, remote_ip: "203.0.113.#{n}", now: @t0)

      assert Auth.authenticate(ned, remote_ip: "203.0.113.6", now: @t0) == {:error, :throttled}
      assert {:ok, _} = Auth.authenticate(oli, remote_ip: "203.0.113.6", now: @t0)
    end

    test "the username key is trimmed and case-folded" do
      {_user, creds} = Fixtures.user!(%{})
      shouted = %{creds | username: " " <> String.upcase(creds.username) <> " "}
      fail_times(shouted, 5, now: @t0)

      assert Auth.authenticate(creds, now: @t0) == {:error, :throttled}
    end

    test "no address, no address key: failures at five usernames don't throttle a sixth" do
      {_user, creds} = Fixtures.user!(%{})

      for n <- 1..5 do
        Auth.authenticate(%{username: "nobody#{n}", password: "x"}, now: @t0)
      end

      assert {:ok, _} = Auth.authenticate(creds, now: @t0)
    end

    test "a success resets the username's count, not the address's" do
      {_user, kim} = Fixtures.user!(%{})
      {_user, lee} = Fixtures.user!(%{})
      ip = [remote_ip: "192.0.2.9"]

      fail_times(kim, 5, ip ++ [now: @t0])
      assert {:ok, _} = Auth.authenticate(kim, remote_ip: "192.0.2.10", now: at(1_000))

      # kim's own count is gone: four more failures leave her free.
      fail_times(kim, 4, remote_ip: "192.0.2.11", now: at(1_000))
      assert {:ok, _} = Auth.authenticate(kim, remote_ip: "192.0.2.11", now: at(1_000))

      # 192.0.2.9's count is not: one more failure from it throttles lee.
      fail_times(kim, 1, ip ++ [now: at(1_000)])
      assert Auth.authenticate(lee, ip ++ [now: at(1_001)]) == {:error, :throttled}
    end

    test "an empty username counts, on one shared key" do
      {_user, creds} = Fixtures.user!(%{})

      for _ <- 1..5 do
        assert Auth.authenticate(%{username: " ", password: "x"},
                 remote_ip: "192.0.2.20",
                 now: @t0
               ) == {:error, :invalid_credentials}
      end

      assert Auth.authenticate(%{username: "", password: "x"}, now: @t0) == {:error, :throttled}
      assert Auth.authenticate(creds, remote_ip: "192.0.2.20", now: @t0) == {:error, :throttled}
    end

    test "a throttled attempt is not checked, emits :throttled, and is not counted" do
      {_user, creds} = Fixtures.user!(%{})
      fail_times(creds, 5, now: @t0)
      rows = length(Ash.read!(Token, action: :macaw_auth_read, authorize?: false))

      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :ash, :authenticate]])
      assert Auth.authenticate(creds, now: @t0) == {:error, :throttled}

      assert_receive {[:macaw_auth, :ash, :authenticate], ^ref, %{count: 1},
                      %{result: :error, reason: :throttled, strategy: nil, user_id: nil}}

      :telemetry.detach(ref)

      # A checked right password leaves a revoked sign-in token; this left none.
      assert length(Ash.read!(Token, action: :macaw_auth_read, authorize?: false)) == rows

      # Not counted: the wait is still five failures' (1 s), not six's.
      assert {:ok, _} = Auth.authenticate(creds, now: at(1_000))
    end

    test "a throttled attempt still spends a hash's time" do
      {_user, blocked} = Fixtures.user!(%{})
      {_user, checked} = Fixtures.user!(%{})
      fail_times(blocked, 5, now: @t0)

      {blocked_us, _} =
        :timer.tc(fn -> for _ <- 1..5, do: Auth.authenticate(blocked, now: @t0) end)

      {checked_us, _} =
        :timer.tc(fn ->
          for _ <- 1..5, do: Auth.authenticate(%{checked | password: "wrong"}, now: @t0)
        end)

      # Same order of time: a skipped hash would be far quicker.
      assert blocked_us > checked_us / 4
    end
  end

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

    test "a session for a user deleted after sign-in is refused, not a crash" do
      {user, _} = Fixtures.user!(%{})
      User |> Ash.get!(user.id, authorize?: false) |> Ash.destroy!(authorize?: false)

      assert Macaw.Auth.Ash.Sessions.create(user, []) == {:error, :invalid}
      assert Auth.create_session(user) == {:error, :invalid}
      assert Ash.read!(Token, action: :macaw_auth_read, authorize?: false) == []
    end

    test "a step on a session that isn't there is invalid, and it stays gone" do
      {user, _} = Fixtures.user!(%{})
      {:ok, by_macaw, revoked} = Auth.create_session(user)
      {:ok, by_ash, revoked_by_ash} = Auth.create_session(user)
      :ok = Auth.revoke(revoked.id)
      :ok = TokenResource.revoke(Token, by_ash)

      for id <- [revoked.id, revoked_by_ash.id, "no-such-jti", 123],
          step <- [:password_change, :second_factor, :second_factor_enroll] do
        assert Auth.complete_step(id, step) == {:error, :invalid}
      end

      assert Auth.fetch(by_macaw) == {:error, :invalid}
      assert Auth.fetch(by_ash) == {:error, :invalid}
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

    test "idle_days is 1 to 3650" do
      for bad <- [0, 3651, 14.5, "14"] do
        assert_raise ArgumentError, ~r/idle_days: .* is not an integer from 1 to 3650/, fn ->
          Config.parse!(user_resource: User, idle_days: bad)
        end
      end

      assert Config.parse!(user_resource: User, idle_days: 1).idle_days == 1
    end

    # The test app's user resource sets token_lifetime {30, :days}.
    test "the token lifetime must be at least idle_days, refused naming both" do
      assert Config.parse!(user_resource: User, idle_days: 30).idle_days == 30

      message =
        "config :macaw_auth, Macaw.Auth.Ash: idle_days: 31 is longer than " <>
          "Macaw.Auth.Ash.Test.User's token_lifetime {30, :days}: sessions would end " <>
          "at the token's expiry before they are idle; set token_lifetime to at least " <>
          "31 days, or idle_days to at most 30"

      assert_raise ArgumentError, message, fn ->
        Config.parse!(user_resource: User, idle_days: 31)
      end
    end

    test "the idle limit the backend reports is idle_days in seconds, the limit it expires by" do
      assert Auth.session_idle_seconds() == 14 * 86_400

      configure(idle_days: 1)
      assert Auth.session_idle_seconds() == 86_400

      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      limit = DateTime.add(session.last_used_at, Auth.session_idle_seconds(), :second)

      assert {:ok, _, _} = Auth.fetch(token, now: limit)
      assert Auth.fetch(token, now: DateTime.add(limit, 1, :second)) == {:error, :expired}
    end

    test "the token resource and domain default to the user resource's" do
      config = Config.parse!(user_resource: User)
      assert {config.token_resource, config.domain} == {Token, Macaw.Auth.Ash.Test.Accounts}
      assert config.username_field == :username
    end
  end
end
