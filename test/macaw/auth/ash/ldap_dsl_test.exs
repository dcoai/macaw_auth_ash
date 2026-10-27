defmodule Macaw.Auth.Ash.Strategy.LdapDslTest do
  @moduledoc """
  The LDAP strategy as declared, without a directory: its DSL, its
  defaults, the fields it checks, and its source, read and parsed at each
  sign-in (a fault raises before anything connects).
  """

  use ExUnit.Case, async: false

  alias Macaw.Auth.Ash.Strategy.Ldap
  alias Macaw.Auth.Ash.Test.{Directory, MinimalLdapUser, User}

  setup do
    {:ok, nas} = AshAuthentication.Info.strategy(User, :nas)
    %{nas: nas}
  end

  @tag verifies: "ash-ldap-plaintext"
  test "a source with starttls off and no allow_plaintext is refused at sign-in", %{nas: nas} do
    plain = %{nas | source: %{Directory.nas() | starttls: false}}

    assert_raise ArgumentError, ~r/allow_plaintext/, fn ->
      Ldap.sign_in(plain, "bob", "bob-password", [])
    end
  end

  @tag verifies: "ash-ldap-dsl"
  test "the DSL's options and defaults, its source read at each sign-in", %{
    nas: nas
  } do
    assert %Ldap{
             name: :nas,
             source: {Directory, :nas, []},
             identity_field: :username,
             roles_field: :roles,
             source_field: :source,
             display_name_field: :display_name,
             disabled_field: :disabled_at,
             sign_in_action_name: :sign_in_with_nas,
             provision_action_name: :provision_with_nas,
             refresh_action_name: :refresh_with_nas,
             resource: User,
             strategy_module: Ldap
           } = nas

    # Only a source set: the name is :ldap, the fields their defaults.
    {:ok, minimal} = AshAuthentication.Info.strategy(MinimalLdapUser, :ldap)

    assert %Ldap{
             identity_field: :username,
             roles_field: :roles,
             source_field: :source,
             display_name_field: nil,
             disabled_field: nil,
             sign_in_action_name: :sign_in_with_ldap,
             provision_action_name: :provision_with_ldap,
             refresh_action_name: :refresh_with_ldap
           } = minimal

    # The source: the function's result or the map, typed :ldap, named after
    # the strategy unless it names itself.
    assert %{name: "nas", host: host} = Ldap.source!(nas)
    assert host == Directory.nas().host
    assert %{name: "nas"} = Ldap.source!(%{nas | source: Directory.nas()})

    assert %{name: "corp"} =
             Ldap.source!(%{nas | source: Map.put(Directory.nas(), :name, "corp")})

    assert_raise ArgumentError, ~r/^LDAP strategy nas: /, fn ->
      Ldap.source!(%{nas | source: Map.delete(Directory.nas(), :host)})
    end
  end

  # Today a field the strategy's actions accept fails Ash's own accept check
  # first (at [:actions, <action>, :accept], "Cannot accept [...]"), and a
  # missing disabled field is only a verifier's compile warning.
  @tag verifies: "ash-ldap-fields"
  @tag deviation:
         "dco-tek/macaw_compose#86: accepted fields fail Ash's accept check first; the disabled field only warns"
  @tag skip: "deviation: the strategy's field errors aren't the ones the spec states"
  test "a named field that isn't an attribute fails to compile at its option's path" do
    for {option, field} <- [
          identity_field: :login,
          roles_field: :groups,
          source_field: :owner,
          display_name_field: :nick,
          disabled_field: :locked_at
        ] do
      source = """
      defmodule Macaw.Auth.Ash.Test.LdapUserWithout_#{option} do
        use Ash.Resource,
          domain: Macaw.Auth.Ash.Test.Elsewhere,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap]

        authentication do
          strategies do
            ldap :corp do
              source({Macaw.Auth.Ash.Test.Directory, :nas, []})
              #{option}(#{inspect(field)})
            end
          end
        end

        attributes do
          uuid_primary_key(:id)
          attribute(:username, :string, allow_nil?: false, public?: true)
          attribute(:roles, {:array, :string}, default: [], public?: true)
          attribute(:source, :string, public?: true)
        end
      end
      """

      error = assert_raise Spark.Error.DslError, fn -> Code.compile_string(source) end
      assert error.path == [:authentication, :strategies, :corp, option]
      assert error.message == "#{inspect(field)} is not an attribute of this resource"
    end
  end
end
