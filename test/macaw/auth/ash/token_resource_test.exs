defmodule Macaw.Auth.Ash.TokenResourceTest do
  @moduledoc """
  `Macaw.Auth.Ash.TokenResource` on the test app's token resource: the
  actions it adds, the one AshAuthentication action it extends
  (log-out-everywhere's), and the notifier it requires.
  """

  use ExUnit.Case, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Ash.{AnnounceRevocation, TokenResource}
  alias Macaw.Auth.Ash.Test.{Fixtures, OwnActionsToken, Token, User}

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

  # Spark runs a resource's verifiers after it compiles and reports their
  # errors as compile warnings, so today the resource below compiles; the
  # spec says it doesn't.
  @tag verifies: "ash-token-verifier-refuses"
  @tag deviation:
         "dco-tek/macaw_compose#86: a Spark verifier's error is a compile warning, not a failure"
  @tag skip: "deviation: the notifier verifier warns at compile time instead of failing"
  test "a token resource without the notifier fails to compile, naming it" do
    source = """
    defmodule Macaw.Auth.Ash.Test.TokenWithoutNotifier do
      use Ash.Resource,
        domain: Macaw.Auth.Ash.Test.Elsewhere,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource]
    end
    """

    assert_raise Spark.Error.DslError, ~r/Macaw\.Auth\.Ash\.Notifier/, fn ->
      Code.compile_string(source)
    end
  end

  # The section's own claim, at its path: the same deviation as above.
  @tag verifies: "ash-token-verifier"
  @tag deviation:
         "dco-tek/macaw_compose#86: a Spark verifier's error is a compile warning, not a failure"
  @tag skip: "deviation: the notifier verifier warns at compile time instead of failing"
  test "the verifier refuses the resource at compile time, at [:notifiers]" do
    source = """
    defmodule Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier do
      use Ash.Resource,
        domain: Macaw.Auth.Ash.Test.Elsewhere,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
        notifiers: []
    end
    """

    error = assert_raise Spark.Error.DslError, fn -> Code.compile_string(source) end
    assert error.path == [:notifiers]
    assert error.module == Macaw.Auth.Ash.Test.AnotherTokenWithoutNotifier
  end
end
