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
  alias Macaw.Auth.Ash.Test.{Fixtures, User}

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

  test "the strategy's own reasons, for logs", %{strategy: strategy} do
    assert {:error, :invalid_credentials, false} =
             Ldap.sign_in(strategy, "alice", "wrong", [])

    assert {:error, :not_in_group, true} = Ldap.sign_in(strategy, "carol", "carol-password", [])
    assert {:error, :empty_password, false} = Ldap.sign_in(strategy, "alice", "", [])
  end

  test "at every sign-in the directory's roles replace the row's" do
    {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})

    row("alice")
    |> Ash.Changeset.for_update(:refresh_with_nas, %{roles: ["owner"]}, authorize?: false)
    |> Ash.update!()

    assert {:ok, %{id: id, roles: ["admin"]}} =
             Auth.authenticate(%{username: "alice", password: "alice-password"})

    assert id == alice.id
  end

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

  test "a disabled directory user stays refused, the row left as it is" do
    {:ok, alice} = Auth.authenticate(%{username: "alice", password: "alice-password"})
    :ok = Fixtures.disable!(alice)

    assert Auth.authenticate(%{username: "alice", password: "alice-password"}) ==
             {:error, :disabled}

    assert Auth.authenticate(%{username: "alice", password: "wrong"}) ==
             {:error, :invalid_credentials}
  end

  test "a directory user's session works as any other" do
    {:ok, bob} = Auth.authenticate(%{username: "bob", password: "bob-password"})
    {:ok, token, session} = Auth.create_session(bob)
    assert {:ok, %{id: id, source: "nas"}, %{id: sid}} = Auth.fetch(token)
    assert {id, sid} == {bob.id, session.id}
  end

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

  test "TLS rules hold: plaintext is refused unless allowed", %{strategy: strategy} do
    plain = %{strategy | source: %{Macaw.Auth.Ash.Test.Directory.nas() | starttls: false}}

    assert_raise ArgumentError, ~r/allow_plaintext/, fn ->
      Ldap.sign_in(plain, "bob", "bob-password", [])
    end

    capture_log(fn ->
      untrusted = %{
        strategy
        | source: Map.delete(Macaw.Auth.Ash.Test.Directory.nas(), :cacertfile)
      }

      assert {:error, :tls_failed, false} = Ldap.sign_in(untrusted, "bob", "bob-password", [])
    end)
  end
end
