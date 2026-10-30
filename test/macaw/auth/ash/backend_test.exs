defmodule Macaw.Auth.Ash.BackendTest do
  @moduledoc """
  What this backend does beyond the kit: its refusals, its users' fields,
  how its sessions sit in the token resource, and how AshAuthentication
  sees them.
  """

  use ExUnit.Case, async: false

  alias AshAuthentication.{Jwt, TokenResource}
  alias Macaw.Auth
  alias Macaw.Auth.Ash.{Config, Sessions}
  alias Macaw.Auth.Ash.Test.{Boot, CompositeKeyUser, Fixtures, Hash, Repo, Token, User}

  setup do
    :ok = Fixtures.reset!()
  end

  defp configure(changes) do
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Ash)
    Application.put_env(:macaw_auth, Macaw.Auth.Ash, Keyword.merge(previous, changes))
    on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Ash, previous) end)
  end

  describe "authenticate" do
    @tag verifies: "ash-authenticate-fields"
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

    @tag verifies: "ash-roles-function"
    test "roles from a function of the record" do
      configure(roles_from: {__MODULE__, :shouted})
      {_user, creds} = Fixtures.user!(%{roles: ["viewer"]})
      assert {:ok, %{roles: ["VIEWER"]}} = Auth.authenticate(creds)
    end

    @tag verifies: "ash-authenticate-disabled"
    test "a disabled user is refused as disabled only with the right password" do
      {user, creds} = Fixtures.user!(%{})
      :ok = Fixtures.disable!(user)

      assert Auth.authenticate(creds) == {:error, :disabled}

      assert Auth.authenticate(%{creds | password: creds.password <> "x"}) ==
               {:error, :invalid_credentials}
    end

    @tag verifies: "ash-authenticate-empty"
    test "an empty or missing username or password is the same refusal, after a hash against nothing" do
      {_user, creds} = Fixtures.user!(%{})

      for bad <- [%{creds | password: ""}, %{creds | username: ""}, %{}, %{username: 1}] do
        assert Hash.work(fn ->
                 assert Auth.authenticate(bad) == {:error, :invalid_credentials}
               end) == [:simulate]
      end
    end

    # The password is the strategy's: AshAuthentication's arguments are
    # Ash strings, trimmed at registration and sign-in alike.
    @tag verifies: "ash-authenticate-trim"
    test "the username is trimmed; the password is checked as AshAuthentication checks it" do
      {_user, creds} = Fixtures.user!(%{})
      assert {:ok, _} = Auth.authenticate(%{creds | username: " #{creds.username} "})
      assert {:ok, _} = Auth.authenticate(%{creds | password: " #{creds.password} "})

      assert Auth.authenticate(%{creds | password: String.upcase(creds.password)}) ==
               {:error, :invalid_credentials}
    end

    @tag verifies: "ash-authenticate-timing"
    # Checked by the verifications that run, never by timing two runs
    # (macaw_auth_ash#1): each is one bcrypt verification's work.
    test "an unknown user and a wrong password each cost one hash" do
      {_user, creds} = Fixtures.user!(%{})

      assert Hash.work(fn ->
               assert Auth.authenticate(%{creds | password: "wrong"}) ==
                        {:error, :invalid_credentials}
             end) == [:valid?]

      assert [:simulate] =
               Hash.work(fn ->
                 assert Auth.authenticate(%{creds | username: "nobody"}) ==
                          {:error, :invalid_credentials}
               end)
    end
  end

  # An elapsed-time read, as a call in code: on a shared runner it measures
  # the runner, so "costs a hash" is checked by the verifications that run
  # (Macaw.Auth.Ash.Test.Hash), never by timing (macaw_auth_ash#1).
  @clocks [{:timer, :tc}, {System, :monotonic_time}, {:erlang, :monotonic_time}]

  defp clocks(source) do
    {_, found} =
      source
      |> Code.string_to_quoted!()
      |> Macro.prewalk([], fn
        {{:., _, [{:__aliases__, _, parts}, fun]}, _, _} = node, acc ->
          {node, [{Module.concat(parts), fun} | acc]}

        {{:., _, [module, fun]}, _, _} = node, acc when is_atom(module) ->
          {node, [{module, fun} | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.filter(found, &(&1 in @clocks))
  end

  @tag verifies: "ash-authenticate-timing"
  test "no test times its code" do
    sources = Path.wildcard("test/**/*.{ex,exs}")
    assert sources != []

    for path <- sources,
        do: assert(clocks(File.read!(path)) == [], "#{path} reads elapsed time")

    # The walk sees a read when there is one, and not one in a comment.
    assert clocks(~S|{us, _} = :timer.tc(fn -> 1 end)|) == [{:timer, :tc}]
    assert clocks(~S|System.monotonic_time(:microsecond)|) == [{System, :monotonic_time}]
    assert clocks("# :timer.tc(f)\n:ok") == []
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

    @tag verifies: "ash-throttle-backoff"
    test "five failures back off: the right password is throttled until the wait has passed" do
      {_user, creds} = Fixtures.user!(%{})
      fail_times(creds, 5, remote_ip: "192.0.2.1", now: @t0)

      assert Auth.authenticate(creds, remote_ip: "192.0.2.1", now: @t0) == {:error, :throttled}

      assert Auth.authenticate(creds, remote_ip: "192.0.2.1", now: at(999)) ==
               {:error, :throttled}

      assert {:ok, _} = Auth.authenticate(creds, remote_ip: "192.0.2.1", now: at(1_000))
    end

    @tag verifies: "ash-throttle-per-address"
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

    @tag verifies: "ash-throttle-per-username"
    test "per username: failures from five addresses throttle a sixth; another user signs in" do
      {_user, ned} = Fixtures.user!(%{})
      {_user, oli} = Fixtures.user!(%{})

      for n <- 1..5, do: fail_times(ned, 1, remote_ip: "203.0.113.#{n}", now: @t0)

      assert Auth.authenticate(ned, remote_ip: "203.0.113.6", now: @t0) == {:error, :throttled}
      assert {:ok, _} = Auth.authenticate(oli, remote_ip: "203.0.113.6", now: @t0)
    end

    @tag verifies: "ash-throttle-normalized"
    test "the username key is trimmed and case-folded" do
      {_user, creds} = Fixtures.user!(%{})
      shouted = %{creds | username: " " <> String.upcase(creds.username) <> " "}
      fail_times(shouted, 5, now: @t0)

      assert Auth.authenticate(creds, now: @t0) == {:error, :throttled}
    end

    @tag verifies: "ash-throttle-no-address"
    test "no address, no address key: failures at five usernames don't throttle a sixth" do
      {_user, creds} = Fixtures.user!(%{})

      for n <- 1..5 do
        Auth.authenticate(%{username: "nobody#{n}", password: "x"}, now: @t0)
      end

      assert {:ok, _} = Auth.authenticate(creds, now: @t0)
    end

    @tag verifies: "ash-throttle-success-resets-user"
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

    @tag verifies: "ash-throttle-empty"
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

    @tag verifies: "ash-throttle-unchecked"
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

    @tag verifies: "ash-throttle-timing"
    test "a throttled attempt still spends a hash's time" do
      {_user, blocked} = Fixtures.user!(%{})
      {_user, checked} = Fixtures.user!(%{})
      fail_times(blocked, 5, now: @t0)

      # The right password, unchecked: one hash against nothing.
      assert Hash.work(fn ->
               assert Auth.authenticate(blocked, now: @t0) == {:error, :throttled}
             end) == [:simulate]

      assert Hash.work(fn ->
               assert Auth.authenticate(%{checked | password: "wrong"}, now: @t0) ==
                        {:error, :invalid_credentials}
             end) == [:valid?]
    end

    # The native throttle's constants, as this backend counts for it: five
    # free failures, then 2^(n-5) seconds from the last, capped at 15 minutes;
    # an attempt waits for the longer of its two keys' waits.
    @tag verifies: "ash-throttle"
    test "the backoff doubles from the last failure to a 15-minute cap; the longer key's wait holds" do
      {_user, creds} = Fixtures.user!(%{})

      last =
        Enum.reduce(1..15, @t0, fn n, last ->
          wait = if n <= 5, do: 0, else: Integer.pow(2, n - 6) * 1_000
          at = DateTime.add(last, wait, :millisecond)

          if wait > 0 do
            early = DateTime.add(at, -1, :millisecond)
            assert Auth.authenticate(creds, now: early) == {:error, :throttled}
          end

          fail_times(creds, 1, now: at)
          at
        end)

      # Fifteen failures would wait 2^10 s; the cap is 900 s.
      assert Auth.authenticate(creds, now: DateTime.add(last, 899_999, :millisecond)) ==
               {:error, :throttled}

      assert {:ok, _} = Auth.authenticate(creds, now: DateTime.add(last, 900_000, :millisecond))

      # pat: five failures from .30 (both keys wait 1 s), a sixth from .31
      # (her username now waits 2 s). From .30 after 1.5 s, the address is
      # free but her username is not; another user from .30 signs in.
      {_user, pat} = Fixtures.user!(%{})
      {_user, quinn} = Fixtures.user!(%{})
      fail_times(pat, 5, remote_ip: "192.0.2.30", now: @t0)
      fail_times(pat, 1, remote_ip: "192.0.2.31", now: at(1_000))

      assert Auth.authenticate(pat, remote_ip: "192.0.2.30", now: at(2_500)) ==
               {:error, :throttled}

      assert {:ok, _} = Auth.authenticate(quinn, remote_ip: "192.0.2.30", now: at(2_500))
      assert {:ok, _} = Auth.authenticate(pat, remote_ip: "192.0.2.30", now: at(3_000))

      # A disabled user's refusals count too, even with the right password.
      {user, ruth} = Fixtures.user!(%{})
      :ok = Fixtures.disable!(user)
      for _ <- 1..5, do: assert(Auth.authenticate(ruth, now: @t0) == {:error, :disabled})
      assert Auth.authenticate(ruth, now: @t0) == {:error, :throttled}
    end
  end

  describe "sessions in the token resource" do
    @tag verifies: "ash-session-row"
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

    @tag verifies: "ash-revoke-both-ways"
    test "AshAuthentication accepts a live session's token and refuses a revoked one" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)

      assert {:ok, _claims, User} = Jwt.verify(token, User)
      refute TokenResource.jti_revoked?(Token, session.id)

      :ok = Auth.revoke(session.id)

      assert TokenResource.jti_revoked?(Token, session.id)
      assert Jwt.verify(token, User) == :error
    end

    @tag verifies: "ash-session-foreign-token"
    test "a token AshAuthentication signed for itself is not a Macaw session" do
      {user, _} = Fixtures.user!(%{})
      record = Ash.get!(User, user.id, authorize?: false)
      {:ok, token, _claims} = Jwt.token_for_user(record, %{"purpose" => "user"})

      assert Auth.fetch(token) == {:error, :invalid}
      assert Auth.list_sessions(user.id) == []
    end

    @tag verifies: "ash-session-touch"
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

    @tag verifies: "ash-session-steps"
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

    @tag verifies: "ash-session-expired"
    test "an expired or disabled session is revoked at its look-up" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      past = DateTime.add(DateTime.utc_now(), 15 * 86_400, :second)

      assert Auth.fetch(token, now: past) == {:error, :expired}
      assert TokenResource.jti_revoked?(Token, session.id)
      assert Auth.fetch(token) == {:error, :invalid}
    end

    @tag verifies: "ash-unsupported"
    test "the second factor is unsupported" do
      {user, _} = Fixtures.user!(%{})
      {:ok, _, session} = Auth.create_session(user)
      assert Auth.verify_second_factor(session.id, "123456") == {:error, :unsupported}
    end

    @tag verifies: "ash-session-deleted-user"
    test "a session for a user deleted after sign-in is refused, not a crash" do
      {user, _} = Fixtures.user!(%{})
      User |> Ash.get!(user.id, authorize?: false) |> Ash.destroy!(authorize?: false)

      assert Macaw.Auth.Ash.Sessions.create(user, []) == {:error, :invalid}
      assert Auth.create_session(user) == {:error, :invalid}
      assert Ash.read!(Token, action: :macaw_auth_read, authorize?: false) == []
    end

    @tag verifies: "ash-session-steps-gone"
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

    @tag verifies: "ash-session-wrong-shape"
    test "ids and tokens of the wrong shape are invalid, never a crash" do
      for bad <- ["", "a.b", "a.b.c", "not a jwt at all", <<255, 0, 1>>] do
        assert Auth.fetch(bad) == {:error, :invalid}
      end

      assert Auth.fetch_by_id(123) == {:error, :invalid}
      assert Auth.fetch_by_id("no-such-jti") == {:error, :invalid}
      assert Auth.revoke("no-such-jti") == :ok
    end

    @tag verifies: "ash-session-not-stored"
    test "no session token is stored as it is, in any column of any token row" do
      {user, _} = Fixtures.user!(%{})
      sessions = for _ <- 1..3, do: Auth.create_session(user, user_agent: "Test/1.0")
      stored = Fixtures.stored_session_values()

      # Plain SQL over every column: each session's jti is among the values.
      for {:ok, _token, session} <- sessions, do: assert(session.id in stored)

      for {:ok, token, _session} <- sessions, value <- stored do
        refute value == token
        refute value == Base.encode64(token)
        refute value == Base.url_encode64(token, padding: false)
        refute String.contains?(value, token)
      end
    end

    @tag verifies: "ash-revoked-by-ash"
    test "a token AshAuthentication revokes is a session Macaw refuses" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)

      :ok = TokenResource.revoke(Token, token)

      assert Auth.fetch(token) == {:error, :invalid}
      assert Auth.fetch_by_id(session.id) == {:error, :invalid}
    end

    @tag verifies: "ash-sessions"
    test "every session function that reads the time takes :now" do
      {user, _} = Fixtures.user!(%{})
      at = ~U[2026-03-01 12:00:00.000000Z]

      {:ok, token, session} = Sessions.create(user, now: at)
      assert {session.created_at, session.last_used_at} == {at, at}

      assert {:ok, _, _} = Sessions.fetch_by_id(session.id, now: DateTime.add(at, 13 * 86_400))
      assert {:ok, _, _} = Sessions.fetch(token, now: DateTime.add(at, 14 * 86_400))

      assert Sessions.fetch(token, now: DateTime.add(at, 14 * 86_400 + 1)) ==
               {:error, :expired}
    end

    @tag verifies: "ash-sessions-token"
    test "a session is one row: the JWT's jti, subject and expiry, with Macaw's metadata" do
      {user, _} = Fixtures.user!(%{})
      at = DateTime.utc_now()
      agent = String.duplicate("a", 300)

      {:ok, token, session} =
        Sessions.create(user, remote_ip: {203, 0, 113, 7}, user_agent: agent, now: at)

      {:ok, claims} = Jwt.peek(token)

      # One row, though the resource stores every token itself: the upsert
      # added Macaw's metadata to the row AshAuthentication stored.
      [row] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false)
      assert {row.jti, row.purpose, row.subject} == {session.id, "user", claims["sub"]}
      # One spelling of the subject: AshAuthentication's own.
      assert row.subject ==
               AshAuthentication.user_to_subject(Ash.get!(User, user.id, authorize?: false))

      assert claims["jti"] == session.id
      assert DateTime.to_unix(row.expires_at) == claims["exp"]

      assert row.extra_data["macaw_auth"] == %{
               "created_at" => DateTime.to_iso8601(at),
               "last_used_at" => DateTime.to_iso8601(at),
               "remote_ip" => "203.0.113.7",
               "user_agent" => String.duplicate("a", 255),
               "second_factor_passed" => true,
               "completed_steps" => []
             }

      refute Enum.any?(Fixtures.stored_session_values(), &String.contains?(&1, token))
    end

    @tag verifies: "ash-sessions-fetch"
    test "a token's row must be its own, with Macaw's metadata; its user is read as now" do
      {user, _} = Fixtures.user!(%{roles: ["viewer"]})
      {other, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)

      # The user as they are now, not as they signed in.
      User
      |> Ash.get!(user.id, authorize?: false)
      |> Ash.Changeset.for_update(:refresh_with_nas, %{roles: ["admin"]}, authorize?: false)
      |> Ash.update!()

      assert {:ok, %{roles: ["admin"]}, _} = Auth.fetch(token)

      # A row whose subject isn't the token's: refused by token; by id, the
      # row's own subject is used.
      {:ok, moved_token, moved} = Auth.create_session(user)

      Repo.query!("UPDATE tokens SET subject = ? WHERE jti = ?", [
        "user?id=#{other.id}",
        moved.id
      ])

      assert Auth.fetch(moved_token) == {:error, :invalid}
      assert {:ok, %{id: other_id}, _} = Auth.fetch_by_id(moved.id)
      assert other_id == other.id

      # A row without Macaw's metadata is no session.
      [row] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false) |> only(session.id)

      row
      |> Ash.Changeset.for_update(:macaw_auth_update, %{extra_data: %{}}, authorize?: false)
      |> Ash.update!()

      assert Auth.fetch(token) == {:error, :invalid}
      assert Auth.fetch_by_id(session.id) == {:error, :invalid}

      # A user gone: their sessions are invalid.
      {:ok, gone_token, gone} = Auth.create_session(other)
      :ok = Fixtures.delete!(other)
      assert Auth.fetch(gone_token) == {:error, :invalid}
      assert Auth.fetch_by_id(gone.id) == {:error, :invalid}
    end

    @tag verifies: "ash-sessions-idle"
    test "a disabled user's session is revoked as :disabled, one past its expiry as :expired, untold" do
      {user, _} = Fixtures.user!(%{})
      {:ok, disabled_token, disabled} = Auth.create_session(user)
      {:ok, kept_token, kept} = Auth.create_session(user)
      :ok = Auth.subscribe(user.id)

      # Not touched by default: two hours on, a look-up without :touch leaves
      # the last use as it was.
      t = kept.last_used_at
      two_hours = DateTime.add(t, 2 * 3_600, :second)
      assert {:ok, _, %{last_used_at: ^t}} = Sessions.fetch(kept_token, now: two_hours)
      assert {:ok, _, %{last_used_at: ^t}} = Sessions.fetch_by_id(kept.id, [])

      # Used every 13 days, it never idles; its row's expiry (the JWT's, 30
      # days) still ends it.

      for days <- [13, 26] do
        assert {:ok, _, _} =
                 Auth.fetch(kept_token, touch: true, now: DateTime.add(t, days * 86_400))
      end

      assert Auth.fetch(kept_token, now: DateTime.add(t, 31 * 86_400)) == {:error, :expired}
      assert TokenResource.jti_revoked?(Token, kept.id)

      :ok = Fixtures.disable!(user)
      assert Auth.fetch(disabled_token) == {:error, :disabled}
      assert TokenResource.jti_revoked?(Token, disabled.id)

      refute_receive {:sessions_revoked, _}
    end

    @tag verifies: "ash-sessions-steps"
    test "enrolling passes the second factor; other steps are kept once, read back only if known" do
      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user, second_factor_passed: false)

      :ok = Auth.complete_step(session.id, :second_factor_enroll)
      :ok = Auth.complete_step(session.id, :password_change)
      :ok = Auth.complete_step(session.id, :password_change)
      :ok = Sessions.complete_step(session.id, :not_a_step, [])

      {:ok, _, read} = Auth.fetch(token)
      assert read.second_factor_passed
      assert read.completed_steps == [:password_change]

      [row] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false)

      assert Enum.sort(row.extra_data["macaw_auth"]["completed_steps"]) ==
               ["not_a_step", "password_change"]
    end

    @tag verifies: "ash-sessions-revoke"
    test "revoking flips live rows, keeping their expiry, and says whose; a list is newest first" do
      {user, _} = Fixtures.user!(%{})
      at = DateTime.utc_now()
      {:ok, _, a} = Sessions.create(user, now: at)
      {:ok, _, b} = Sessions.create(user, now: at)
      {:ok, _, c} = Sessions.create(user, now: DateTime.add(at, 1))

      # Newest first; a tie in created_at broken by id.
      assert Enum.map(Sessions.list(user.id, []), & &1.id) ==
               [c.id | Enum.sort([a.id, b.id], :desc)]

      [live] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false) |> only(a.id)

      assert Sessions.revoke(a.id, []) == {user.id, [a.id]}
      assert Sessions.revoke(a.id, []) == {nil, []}
      assert Sessions.revoke(123, []) == {nil, []}

      [revoked] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false) |> only(a.id)
      assert {revoked.purpose, revoked.expires_at} == {"revocation", live.expires_at}

      assert Sessions.revoke({:user, user.id}, except: c.id) == {user.id, [b.id]}
      assert Sessions.revoke({:user, user.id}, []) == {user.id, [c.id]}
      assert Sessions.revoke({:user, user.id}, []) == {user.id, []}

      # Found by the subject made from the id alone: a deleted user's too.
      {:ok, _, d} = Sessions.create(user, [])
      :ok = Fixtures.delete!(user)
      assert [%{id: id}] = Sessions.list(user.id, [])
      assert id == d.id

      assert Sessions.subject_user_id("user?id=#{user.id}", User) == {:ok, user.id}
      assert Sessions.subject_user_id("other?id=1", User) == :error
    end
  end

  defp only(rows, jti), do: Enum.filter(rows, &(&1.jti == jti))

  describe "the backend" do
    @tag verifies: "ash-backend"
    test "every backend callback is Macaw.Auth.Ash's, over resources no actor may touch" do
      Code.ensure_loaded!(Macaw.Auth.Ash)

      {:docs_v1, _, _, _, _, _, docs} = Code.fetch_docs(Macaw.Auth.Backend)
      callbacks = for {{:callback, name, arity}, _, _, _, _} <- docs, do: {name, arity}
      assert length(callbacks) == 10

      for {name, arity} <- callbacks do
        assert function_exported?(Macaw.Auth.Ash, name, arity), "#{name}/#{arity}"
      end

      assert Macaw.Auth.Ash.session_idle_seconds([]) == 14 * 86_400

      # The test app's resources forbid every actor (their policies), so each
      # call below succeeds only because the backend makes every read and
      # write with authorize?: false.
      assert {:error, %Ash.Error.Forbidden{}} = Ash.read(User)
      assert {:error, %Ash.Error.Forbidden{}} = Ash.read(Token, action: :macaw_auth_read)

      {_user, creds} = Fixtures.user!(%{})
      {:ok, user} = Auth.authenticate(creds)
      {:ok, token, session} = Auth.create_session(user)
      later = DateTime.add(session.last_used_at, 2 * 3_600, :second)
      assert {:ok, _, %{last_used_at: ^later}} = Auth.fetch(token, touch: true, now: later)
      assert {:ok, _, _} = Auth.fetch_by_id(session.id, now: later)
      assert [_] = Auth.list_sessions(user.id)
      assert Auth.complete_step(session.id, :password_change) == :ok
      assert Auth.verify_second_factor(session.id, "123456") == {:error, :unsupported}
      assert Auth.revoke({:user, user.id}) == :ok
      assert Auth.list_sessions(user.id) == []

      # check_config!/0 checks the whole configuration: the test app's is
      # sound, and a fault raises, naming it.
      assert Macaw.Auth.Ash.check_config!() == :ok
      configure(idle_days: 0)

      assert_raise ArgumentError,
                   ~r/idle_days: 0 is not an integer/,
                   &Macaw.Auth.Ash.check_config!/0
    end

    @tag verifies: "ash-second-factor"
    test "the second factor is pending: none reported or owed, every code refused, none made" do
      {_user, creds} = Fixtures.user!(%{})
      {:ok, user} = Auth.authenticate(creds)
      assert user.second_factor == :none

      {:ok, _token, session} = Auth.create_session(user, second_factor_passed: false)
      assert Auth.pending_step(user, session) == nil

      for code <- ["123456", "000000", "999999"] do
        assert Auth.verify_second_factor(session.id, code) == {:error, :unsupported}
      end

      for level <- [:enrolled, :required] do
        assert_raise ArgumentError, ~r/second_factor/, fn ->
          Fixtures.user!(%{second_factor: level})
        end
      end
    end

    @tag verifies: "ash-to-user"
    test "to_user/2 maps a record by the configured fields, with no second factor" do
      {user, _} = Fixtures.user!(%{display_name: "Ada", roles: ["admin"]})
      record = Ash.get!(User, user.id, authorize?: false)

      # With no optional fields configured: no display name, every user local.
      bare = Config.parse!(user_resource: User)

      assert %Auth.User{
               display_name: nil,
               source: "local",
               roles: ["admin"],
               disabled: false,
               second_factor: :none,
               must_change_password: false,
               extra: %{}
             } = mapped = Macaw.Auth.Ash.to_user(%{record | source: "nas"}, bare)

      assert {mapped.id, mapped.username} == {record.id, record.username}

      full = Config.get()

      assert %{display_name: "Ada", source: "nas"} =
               Macaw.Auth.Ash.to_user(%{record | source: "nas"}, full)

      assert Macaw.Auth.Ash.to_user(%{record | roles: nil}, full).roles == []

      for {value, disabled} <- [{nil, false}, {false, false}, {true, true}, {at(0), true}] do
        assert Macaw.Auth.Ash.to_user(%{record | disabled_at: value}, full).disabled == disabled
      end
    end

    @tag verifies: "ash-must-change-unmapped"
    test "no user owes a password change: must_change_password is false, a session owes nothing" do
      {_user, creds} = Fixtures.user!(%{})
      {:ok, user} = Auth.authenticate(creds)
      refute user.must_change_password

      {:ok, _token, session} = Auth.create_session(user)
      assert Auth.pending_step(user, session) == nil
    end

    @tag verifies: "ash-known"
    test "this release's limits: no second factor, no password change, no generator, a row per sign-in" do
      {_user, creds} = Fixtures.user!(%{})
      {:ok, user} = Auth.authenticate(creds)
      {:ok, ^user} = Auth.authenticate(creds)

      # Each password sign-in leaves its discarded token's revocation row.
      purposes =
        Token
        |> Ash.read!(action: :macaw_auth_read, authorize?: false)
        |> Enum.map(& &1.purpose)

      assert purposes == ["revocation", "revocation"]

      refute user.must_change_password
      {:ok, _token, session} = Auth.create_session(user)
      assert Auth.pending_step(user, session) == nil
      assert Auth.verify_second_factor(session.id, "123456") == {:error, :unsupported}

      # No generator: the library ships no Mix task.
      {:ok, modules} = :application.get_key(:macaw_auth_ash, :modules)
      refute Enum.any?(modules, &String.starts_with?(inspect(&1), "Mix.Tasks."))
    end
  end

  describe "configuration" do
    @tag verifies: "ash-check-config-boot"
    test "checked at boot: a fault refuses to start, naming it; the test app's starts" do
      assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%ArgumentError{} = e, _}}}}}} =
               Boot.boot_with(idle_days: 0)

      assert Exception.message(e) ==
               "config :macaw_auth, Macaw.Auth.Ash: idle_days: 0 is not an integer from 1 to 3650"

      assert Macaw.Auth.Ash.check_config!() == :ok
      assert {:ok, _} = Boot.boot_with([])
    end

    @tag verifies: "ash-config-faults"
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

    @tag verifies: "ash-config-idle-bounds"
    test "idle_days is 1 to 3650" do
      for bad <- [0, 3651, 14.5, "14"] do
        assert_raise ArgumentError, ~r/idle_days: .* is not an integer from 1 to 3650/, fn ->
          Config.parse!(user_resource: User, idle_days: bad)
        end
      end

      assert Config.parse!(user_resource: User, idle_days: 1).idle_days == 1
    end

    # The test app's user resource sets token_lifetime {30, :days}.
    @tag verifies: "ash-config-token-lifetime"
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

    @tag verifies: "ash-idle-seconds"
    test "the idle limit the backend reports is idle_days in seconds, the limit it expires by" do
      assert Auth.session_idle_seconds() == 14 * 86_400
      # The kit's check: the backend's limit is the fixtures' idle_seconds/0.
      assert Auth.session_idle_seconds() == Fixtures.idle_seconds()

      configure(idle_days: 1)
      assert Auth.session_idle_seconds() == 86_400
      assert Auth.session_idle_seconds() == Fixtures.idle_seconds()

      {user, _} = Fixtures.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      limit = DateTime.add(session.last_used_at, Auth.session_idle_seconds(), :second)

      assert {:ok, _, _} = Auth.fetch(token, now: limit)
      assert Auth.fetch(token, now: DateTime.add(limit, 1, :second)) == {:error, :expired}
    end

    @tag verifies: "ash-config-defaults"
    test "the token resource and domain default to the user resource's" do
      config = Config.parse!(user_resource: User)
      assert {config.token_resource, config.domain} == {Token, Macaw.Auth.Ash.Test.Accounts}
      assert [%AshAuthentication.Strategy.Password{name: :password}] = config.strategies
      assert config.username_field == :username
    end

    # The section's own text: read on every call, the faults' prefix, and
    # the checks the hints above don't name.
    @tag verifies: "ash-config"
    test "read and checked on every call; every fault an ArgumentError naming it" do
      assert Config.get().idle_days == 14
      configure(idle_days: 3)
      assert Config.get().idle_days == 3

      faults = [
        {[token_resource: Token], "user_resource is required"},
        {[user_resource: String], "user_resource: String is not an Ash resource"},
        {[user_resource: User, token_resource: User],
         "token_resource Macaw.Auth.Ash.Test.User needs the Macaw.Auth.Ash.TokenResource extension"},
        {[user_resource: User, strategies: []],
         "set one of strategy (a name) or strategies (a non-empty list)"},
        {[user_resource: User, strategy: :password, strategies: [:password]],
         "set one of strategy (a name) or strategies (a non-empty list)"},
        {[user_resource: User, strategy: :log_out_everywhere],
         "strategy :log_out_everywhere is a AshAuthentication.AddOn.LogOutEverywhere"},
        {[user_resource: User, username_field: :nope],
         "username_field: :nope is not an attribute of Macaw.Auth.Ash.Test.User"},
        {[user_resource: User, roles_from: {__MODULE__, :absent}],
         "roles_from: Macaw.Auth.Ash.BackendTest.absent/1 is not defined"},
        {[user_resource: User, roles_from: "roles"],
         ~s(roles_from: "roles" is neither an attribute nor {module, function})},
        {[user_resource: CompositeKeyUser],
         "user_resource needs a single-attribute primary key, not [:tenant, :username]"}
      ]

      for {settings, fault} <- faults do
        assert_raise ArgumentError, "config :macaw_auth, Macaw.Auth.Ash: " <> fault, fn ->
          Config.parse!(settings)
        end
      end

      # One strategy by name, an attribute or a function for roles, and the
      # optional fields named.
      config =
        Config.parse!(
          user_resource: User,
          strategy: :password,
          roles_from: {__MODULE__, :shouted},
          display_name_field: :display_name,
          source_field: :source,
          disabled_field: :disabled_at
        )

      assert [%{name: :password}] = config.strategies
      assert config.roles_from == {__MODULE__, :shouted}
      assert {config.display_name_field, config.source_field} == {:display_name, :source}
      assert {config.primary_key, config.idle_days} == {:id, 14}
    end
  end
end
