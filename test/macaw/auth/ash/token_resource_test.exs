defmodule Macaw.Auth.Ash.TokenResourceTest do
  @moduledoc """
  `Macaw.Auth.Ash.TokenResource` on the test app's token resource: the
  actions it adds, the one AshAuthentication action it extends
  (log-out-everywhere's), and the notifier it requires.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Macaw.Auth
  alias Macaw.Auth.Ash.{AnnounceRevocation, Config, TokenResource}
  alias Macaw.Auth.Ash.Test.{Boot, Fixtures, OwnActionsToken, Token, User}

  setup do
    :ok = Fixtures.reset!()
  end

  @tag verifies: "ash-token-actions-added"
  test "its actions: the primary read, an update of extra_data, a revocation keeping the expiry" do
    assert %{name: :macaw_auth_read, primary?: true} =
             Ash.Resource.Info.primary_action(Token, :read)

    assert %{type: :update, accept: accept} = Ash.Resource.Info.action(Token, :macaw_auth_update)
    assert :extra_data in accept
    assert %{type: :update} = Ash.Resource.Info.action(Token, :macaw_auth_revoke)

    {user, _} = Fixtures.user!(%{})
    {:ok, _token, _session} = Auth.create_session(user)
    [row] = Ash.read!(Token, action: :macaw_auth_read, authorize?: false)

    revoked =
      row
      |> Ash.Changeset.for_update(:macaw_auth_revoke, %{}, authorize?: false)
      |> Ash.update!()

    assert revoked.purpose == "revocation"
    assert revoked.expires_at == row.expires_at
  end

  @tag verifies: "ash-token-log-out-everywhere"
  test "log-out-everywhere, a bulk update over the primary read, revokes every session" do
    {user, _} = Fixtures.user!(%{})
    {:ok, first, _} = Auth.create_session(user)
    {:ok, second, _} = Auth.create_session(user)

    {:ok, strategy} = AshAuthentication.Info.strategy(User, :log_out_everywhere)
    record = Ash.get!(User, user.id, authorize?: false)
    :ok = AshAuthentication.Strategy.action(strategy, :log_out_everywhere, %{user: record})

    assert Auth.list_sessions(user.id) == []
    assert Auth.fetch(first) == {:error, :invalid}
    assert Auth.fetch(second) == {:error, :invalid}
  end

  @tag verifies: "ash-token-actions"
  test "its actions come after AshAuthentication's, leave a host's own, and mark the resource" do
    assert {TokenResource.read_action(), TokenResource.update_action(),
            TokenResource.revoke_action()} ==
             {:macaw_auth_read, :macaw_auth_update, :macaw_auth_revoke}

    transformer = Macaw.Auth.Ash.TokenResource.Transformer
    assert transformer.after?(AshAuthentication.TokenResource.Transformer)
    assert transformer.before?(Ash.Resource.Transformers.DefaultAccept)

    # The revocation accepts nothing; the change rides on log-out-everywhere's action.
    assert %{accept: []} = Ash.Resource.Info.action(Token, :macaw_auth_revoke)

    revoke_all =
      AshAuthentication.TokenResource.Info.token_revocation_revoke_all_stored_for_subject_action_name!(
        Token
      )

    assert Ash.Resource.Info.action(Token, revoke_all).changes
           |> Enum.count(&match?(%{change: {AnnounceRevocation, _}}, &1)) == 1

    # Marked, as Macaw.Auth.Ash.Config requires of the token resource.
    assert Spark.Dsl.Extension.get_persisted(Token, :macaw_auth_ash_token?)

    # A host's own action of a name is left as it is; the others are added.
    assert %{description: "the host's own"} =
             Ash.Resource.Info.action(OwnActionsToken, :macaw_auth_update)

    assert %{primary?: true} = Ash.Resource.Info.action(OwnActionsToken, :macaw_auth_read)
    assert %{type: :update} = Ash.Resource.Info.action(OwnActionsToken, :macaw_auth_revoke)
  end

  # Spark reports a verifier's error as a compile warning, so the resource
  # compiles under default build flags; Config refuses it whatever they are.
  @tag verifies: "ash-token-verifier-refuses"
  test "a token resource without the notifier: warned at compile time, refused at load" do
    warnings =
      capture_io(:stderr, fn ->
        Code.compile_string("""
        defmodule Macaw.Auth.Ash.Test.TokenWithoutNotifier do
          use Ash.Resource,
            domain: Macaw.Auth.Ash.Test.Elsewhere,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource]
        end
        """)
      end)

    assert warnings =~ "Macaw.Auth.Ash.Notifier"

    assert_raise ArgumentError,
                 "config :macaw_auth, Macaw.Auth.Ash: token_resource " <>
                   "Macaw.Auth.Ash.Test.TokenWithoutNotifier needs Macaw.Auth.Ash.Notifier " <>
                   "among its notifiers",
                 fn ->
                   Config.parse!(
                     user_resource: User,
                     token_resource: Macaw.Auth.Ash.Test.TokenWithoutNotifier
                   )
                 end
  end

  @tag verifies: "ash-token-verifier-boot"
  test "a token resource without the notifier, configured: :macaw_auth refuses to start" do
    capture_io(:stderr, fn ->
      Code.compile_string("""
      defmodule Macaw.Auth.Ash.Test.BootTokenWithoutNotifier do
        use Ash.Resource,
          domain: Macaw.Auth.Ash.Test.Elsewhere,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource]
      end
      """)
    end)

    assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%ArgumentError{} = e, _}}}}}} =
             Boot.boot_with(token_resource: Macaw.Auth.Ash.Test.BootTokenWithoutNotifier)

    assert Exception.message(e) ==
             "config :macaw_auth, Macaw.Auth.Ash: token_resource " <>
               "Macaw.Auth.Ash.Test.BootTokenWithoutNotifier needs Macaw.Auth.Ash.Notifier " <>
               "among its notifiers"
  end

  # The section's own claims: the verifier's warning at [:notifiers], and
  # the configuration's refusal, both naming the resource.
  @tag verifies: "ash-token-verifier"
  test "the verifier warns at [:notifiers], and Config refuses the resource at load" do
    warnings =
      capture_io(:stderr, fn ->
        Code.compile_string("""
        defmodule Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier do
          use Ash.Resource,
            domain: Macaw.Auth.Ash.Test.Elsewhere,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
            notifiers: []
        end
        """)
      end)

    assert warnings =~ "[Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier]\nnotifiers :"
    assert warnings =~ "needs its notifier"

    error =
      assert_raise ArgumentError, fn ->
        Config.parse!(
          user_resource: User,
          token_resource: Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier
        )
      end

    assert error.message =~ "Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier"
    assert error.message =~ "Macaw.Auth.Ash.Notifier"

    # The test app's token resource, which has the notifier, is accepted.
    assert %{token_resource: Token} = Config.parse!(user_resource: User, token_resource: Token)
  end
end
