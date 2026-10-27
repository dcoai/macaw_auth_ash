defmodule Macaw.Auth.Ash.Strategy.LdapTest do
  @moduledoc """
  The LDAP strategy against the OpenLDAP fixture directory (macaw's
  ci/tools/ldap image; users under cn=users, posixGroup groups with
  memberUid under cn=groups), as the test app's `nas` strategy
  (`Macaw.Auth.Ash.Test.Directory`). Runs when MACAW_AUTH_LDAP_HOST names
  it (CI's `ldap` service):

      docker run -d --rm --name macaw-auth-ldap -p 127.0.0.1:3391:389 \\
        -p 127.0.0.1:3638:636 macaw-ldap-test
      MACAW_AUTH_LDAP_HOST=localhost MACAW_AUTH_LDAP_PORT=3391 \\
        MACAW_AUTH_LDAPS_PORT=3638 mix test --include ldap
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.Errors.AuthenticationFailed
  alias Macaw.Auth
  alias Macaw.Auth.Ash.Strategy.Ldap
  alias Macaw.Auth.Ash.Test.{Directory, Fixtures, Token, User}

  @moduletag :ldap

  setup do
    :ok = Fixtures.reset!()
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Ash)

    Application.put_env(
      :macaw_auth,
      Macaw.Auth.Ash,
      Keyword.put(previous, :strategies, [:password, :nas])
    )

    on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Ash, previous) end)
    {:ok, strategy} = AshAuthentication.Info.strategy(User, :nas)
    %{strategy: strategy}
  end

  defp row(username) do
    User
    |> Ash.Query.for_read(:read, %{}, authorize?: false)
    |> Ash.Query.filter_input(%{username: username})
    |> Ash.read_one!(authorize?: false)
  end

  @tag verifies: "ash-ldap-provision-first"
  test "a directory user signs in, provisioned with the directory's roles" do
    assert {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})

    assert %Auth.User{username: "alice", roles: ["admin"], source: "nas"} = alice
    assert alice.display_name == "Alice Admin"

    record = row("alice")
    assert record.id == alice.id
    assert {record.source, record.roles} == {"nas", ["admin"]}

    assert {:ok, %{roles: ["viewer"], source: "nas"}} =
             Auth.authenticate(%{username: "bob", password: "bob-password"})
  end

  @tag verifies: "ash-ldap-refusals"
  test "a wrong password, an unknown user, a user outside the required group: one refusal" do
    for {username, password} <- [
          {"alice", "wrong"},
          {"nobody", "x"},
          {"carol", "carol-password"},
          {"alice,cn=users", "alice-password"}
        ] do
      assert Auth.authenticate(%{username: username, password: password}) ==
               {:error, :invalid_credentials}
    end

    assert row("carol") == nil
  end

  @tag verifies: "ash-ldap-reasons"
  test "the strategy's own reasons, for logs", %{strategy: strategy} do
    assert {:error, :invalid_credentials, false} =
             Ldap.sign_in(strategy, "alice", "wrong", [])

    assert {:error, :not_in_group, true} = Ldap.sign_in(strategy, "carol", "carol-password", [])
    assert {:error, :empty_password, false} = Ldap.sign_in(strategy, "alice", "", [])
  end

  @tag verifies: "ash-ldap-refresh"
  test "at every sign-in the directory's roles replace the row's" do
    {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})

    row("alice")
    |> Ash.Changeset.for_update(:refresh_with_nas, %{roles: ["owner"]}, authorize?: false)
    |> Ash.update!()

    assert {:ok, %{id: id, roles: ["admin"]}} =
             Auth.authenticate(%{username: "alice", password: "alice-password"})

    assert id == alice.id
  end

  @tag verifies: "ash-ldap-no-takeover"
  test "a row another source owns is never taken over" do
    {_local, _} = Fixtures.user!(%{username: "bob"})

    assert Auth.authenticate(%{username: "bob", password: "bob-password"}) ==
             {:error, :invalid_credentials}

    User
    |> Ash.Changeset.for_create(:seed, %{username: "alice", source: "other", roles: ["x"]},
      authorize?: false
    )
    |> Ash.create!()

    assert Auth.authenticate(%{username: "alice", password: "alice-password"}) ==
             {:error, :invalid_credentials}

    assert %{source: "other", roles: ["x"]} = row("alice")
  end

  @tag verifies: "ash-ldap-disabled"
  test "a disabled directory user stays refused, the row left as it is" do
    {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})
    :ok = Fixtures.disable!(alice)

    assert Auth.authenticate(%{username: "alice", password: "alice-password"}) ==
             {:error, :disabled}

    assert Auth.authenticate(%{username: "alice", password: "wrong"}) ==
             {:error, :invalid_credentials}
  end

  @tag verifies: "ash-ldap-session"
  test "a directory user's session works as any other" do
    {:ok, bob} = Auth.authenticate(%{username: "bob", password: "bob-password"})
    {:ok, token, session} = Auth.create_session(bob)
    assert {:ok, %{id: id, source: "nas"}, %{id: sid}} = Auth.fetch(token)
    assert {id, sid} == {bob.id, session.id}
  end

  @tag verifies: "ash-ldap-action"
  test "through AshAuthentication: the action signs a user token, refusals are AuthenticationFailed",
       %{strategy: strategy} do
    params = %{"username" => "bob", "password" => "bob-password"}
    assert {:ok, record} = AshAuthentication.Strategy.action(strategy, :sign_in, params)
    assert record.username == "bob"
    assert {:ok, _claims, User} = AshAuthentication.Jwt.verify(record.__metadata__.token, User)

    wrong = %{params | "password" => "wrong"}
    assert {:error, error} = AshAuthentication.Strategy.action(strategy, :sign_in, wrong)
    assert Enum.any?(error.errors, &match?(%AuthenticationFailed{}, &1))

    assert [{"/user/nas", :sign_in}] = AshAuthentication.Strategy.routes(strategy)
  end

  # Plaintext refused unless allowed: Macaw.Auth.Ash.Strategy.LdapDslTest,
  # which needs no directory.
  @tag verifies: "ash-ldap-tls"
  test "TLS rules hold: without the directory's CA, TLS fails", %{strategy: strategy} do
    capture_log(fn ->
      untrusted = %{strategy | source: Map.delete(Directory.nas(), :cacertfile)}

      assert {:error, :tls_failed, false} = Ldap.sign_in(untrusted, "bob", "bob-password", [])
    end)
  end

  # The backend's sign-in (spec 01 §2) over both strategies: which decides,
  # and what each attempt tells.
  @tag verifies: "ash-authenticate"
  test "the first strategy that knows the user decides; each attempt is told, never its secrets" do
    {_local, _} = Fixtures.user!(%{username: "bob"})
    ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :ash, :authenticate]])

    told = fn ->
      assert_receive {[:macaw_auth, :ash, :authenticate], ^ref, %{count: 1}, meta}
      meta
    end

    # A local user's refusal is final: the directory's bob is never tried.
    assert Auth.authenticate(%{username: "bob", password: "bob-password"}) ==
             {:error, :invalid_credentials}

    assert told.() ==
             %{result: :error, reason: :invalid_credentials, strategy: :password, user_id: nil}

    # A provisioned row has no password: the password strategy passes it on,
    # at the first sign-in and every later one.
    for _ <- 1..2 do
      assert {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})
      assert told.() == %{result: :ok, reason: nil, strategy: :nas, user_id: alice.id}
    end

    # None knows the user: the last refusal stands.
    assert Auth.authenticate(%{username: "nobody", password: "x"}) ==
             {:error, :invalid_credentials}

    assert %{result: :error, strategy: :nas, user_id: nil} = told.()

    # A provisioning refusal is :invalid_credentials too.
    User
    |> Ash.Changeset.for_create(:seed, %{username: "carol", source: "other"}, authorize?: false)
    |> Ash.create!()

    assert Auth.authenticate(%{username: "carol", password: "carol-password"}) ==
             {:error, :invalid_credentials}

    assert %{result: :error, strategy: :nas} = told.()

    # An empty field never reaches a strategy.
    assert Auth.authenticate(%{username: "alice", password: ""}) ==
             {:error, :invalid_credentials}

    assert told.() == %{result: :error, reason: :empty, strategy: nil, user_id: nil}

    :telemetry.detach(ref)

    # An empty field still spends a hash's time (the password strategy's
    # simulate/0): the same order as a local user's wrong password (four of
    # each, on two users, under the throttle).
    {_user, emptied} = Fixtures.user!(%{})
    {_user, mistyped} = Fixtures.user!(%{})
    empty = %{emptied | password: ""}
    wrong = %{mistyped | password: "wrong"}
    {empty_us, _} = :timer.tc(fn -> for _ <- 1..4, do: Auth.authenticate(empty) end)
    {wrong_us, _} = :timer.tc(fn -> for _ <- 1..4, do: Auth.authenticate(wrong) end)
    assert empty_us > wrong_us / 4

    # The address may be a tuple: it counts as its string.
    for n <- 1..5 do
      Auth.authenticate(%{username: "nobody#{n}", password: "x"}, remote_ip: {198, 51, 100, 9})
    end

    assert Auth.authenticate(%{username: "alice", password: "alice-password"},
             remote_ip: "198.51.100.9"
           ) == {:error, :throttled}
  end

  @tag verifies: "ash-ldap"
  test "the native LDAP source on the user resource: escaping, TLS, groups, roles, provisioning",
       %{strategy: strategy} do
    assert row("bob") == nil

    # Provisioned at the first sign-in; roles by the mapping, else the default.
    assert {:ok, %User{username: "bob", roles: ["viewer"], source: "nas"}} =
             Ldap.sign_in(strategy, "bob", "bob-password", [])

    assert %{source: "nas"} = row("bob")

    assert {:ok, %User{roles: ["admin"]}} =
             Ldap.sign_in(strategy, "alice", "alice-password", [])

    # The required group, and the DN escaped: nothing provisioned for either.
    assert {:error, :not_in_group, true} = Ldap.sign_in(strategy, "carol", "carol-password", [])

    assert {:error, _reason, _knows?} =
             Ldap.sign_in(strategy, "alice,cn=users", "alice-password", [])

    assert row("carol") == nil and row("alice,cn=users") == nil

    # The TLS rules: plaintext refused unless allowed.
    assert_raise ArgumentError, ~r/allow_plaintext/, fn ->
      Ldap.sign_in(%{strategy | source: %{Directory.nas() | starttls: false}}, "bob", "x", [])
    end
  end

  @tag verifies: "ash-ldap-actions"
  test "the actions it builds, and the phase it registers; Macaw signs no extra token",
       %{strategy: strategy} do
    # Through Macaw.Auth, sign_in/4 directly: no token signed, no row stored.
    {:ok, _} = Auth.authenticate(%{username: "bob", password: "bob-password"})
    assert Ash.read!(Token, action: :macaw_auth_read, authorize?: false) == []

    sign_in = Ash.Resource.Info.action(User, :sign_in_with_nas)
    assert sign_in.type == :action

    assert [
             %{name: :username, type: Ash.Type.String, sensitive?: false},
             %{name: :password, type: Ash.Type.String, sensitive?: true}
           ] = sign_in.arguments

    assert %{type: :create, accept: provision} =
             Ash.Resource.Info.action(User, :provision_with_nas)

    assert Enum.sort(provision) == [:display_name, :roles, :source, :username]
    assert %{type: :update, accept: refresh} = Ash.Resource.Info.action(User, :refresh_with_nas)
    assert Enum.sort(refresh) == [:display_name, :roles]

    assert AshAuthentication.Strategy.phases(strategy) == [:sign_in]
    assert AshAuthentication.Strategy.method_for_phase(strategy, :sign_in) == :post
    refute AshAuthentication.Strategy.tokens_required?(strategy)

    # Its plug reads the params under the subject's key, as the password
    # strategy's sign-in does.
    conn =
      Plug.Test.conn(:post, "/user/nas", %{
        "user" => %{"username" => "bob", "password" => "bob-password"}
      })

    conn = AshAuthentication.Strategy.plug(strategy, :sign_in, conn)
    assert {:ok, %User{username: "bob"}} = conn.private[:authentication_result]

    # A context asking for no user token gets none.
    params = %{"username" => "bob", "password" => "bob-password"}

    assert {:ok, record} =
             AshAuthentication.Strategy.action(strategy, :sign_in, params,
               context: %{token_type: :none}
             )

    refute record.__metadata__[:token]

    # Every refusal is the one AuthenticationFailed, its reason in caused_by.
    for {username, password, reason} <- [
          {"alice", "wrong", :invalid_credentials},
          {"nobody", "x", :invalid_credentials},
          {"carol", "carol-password", :not_in_group}
        ] do
      assert {:error, error} =
               AshAuthentication.Strategy.action(strategy, :sign_in, %{
                 "username" => username,
                 "password" => password
               })

      assert [%AuthenticationFailed{caused_by: %{reason: ^reason}}] =
               Enum.filter(error.errors, &match?(%AuthenticationFailed{}, &1))
    end
  end

  @tag verifies: "ash-ldap-sign-in"
  test "sign_in/4: the record, or the reason and whether it is final; explain_refusal/1 for logs",
       %{strategy: strategy} do
    assert {:ok, %User{username: "bob"}} = Ldap.sign_in(strategy, "bob", "bob-password", [])

    # Whether a refusal is final is the source's knows?/2: an unknown entry
    # under a direct bind, or an unreachable directory, passes on.
    assert {:error, :invalid_credentials, false} = Ldap.sign_in(strategy, "nobody", "x", [])

    capture_log(fn ->
      unreachable = %{strategy | source: %{Directory.nas() | port: 1}}

      assert {:error, :connect_failed, false} =
               Ldap.sign_in(unreachable, "bob", "bob-password", [])
    end)

    # A provisioning refusal is always final.
    {_local, _} = Fixtures.user!(%{username: "alice"})

    assert {:error, :username_taken, true} =
             Ldap.sign_in(strategy, "alice", "alice-password", [])

    :ok = Fixtures.disable!(row("bob"))
    assert {:error, :disabled, true} = Ldap.sign_in(strategy, "bob", "bob-password", [])

    assert Ldap.explain_refusal(:username_taken) ==
             "a user with that username belongs to another source"

    assert Ldap.explain_refusal(:disabled) == "the user is disabled"

    assert Ldap.explain_refusal(:not_in_group) ==
             Macaw.Auth.Native.Source.Ldap.explain(:not_in_group)
  end

  @tag verifies: "ash-ldap-provision"
  test "a row provisioned without a password, refreshed at each sign-in, keeping nothing else" do
    {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})

    row("alice")
    |> Ash.Changeset.for_update(:refresh_with_nas, %{display_name: "Someone", roles: ["x"]},
      authorize?: false
    )
    |> Ash.update!()

    {:ok, _} = Auth.authenticate(%{username: "alice", password: "alice-password"})

    # Exactly what the row holds: the directory's username, roles, display
    # name and source, no password; its DN, ids, email and groups nowhere.
    record = row("alice")

    assert Map.take(record, [
             :id,
             :username,
             :hashed_password,
             :display_name,
             :roles,
             :source,
             :disabled_at
           ]) == %{
             id: alice.id,
             username: "alice",
             hashed_password: nil,
             display_name: "Alice Admin",
             roles: ["admin"],
             source: "nas",
             disabled_at: nil
           }

    assert User |> Ash.Resource.Info.attributes() |> Enum.map(& &1.name) |> Enum.sort() ==
             [:disabled_at, :display_name, :hashed_password, :id, :roles, :source, :username]

    # The identity on the username: a second row for it is refused.
    assert {:error, _} =
             User
             |> Ash.Changeset.for_create(
               :provision_with_nas,
               %{username: "alice", roles: [], source: "nas"},
               authorize?: false
             )
             |> Ash.create()
  end
end
