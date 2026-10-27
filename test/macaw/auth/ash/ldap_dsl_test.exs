defmodule Macaw.Auth.Ash.Strategy.LdapDslTest do
  @moduledoc """
  The LDAP strategy as declared, without a directory: its DSL, its
  defaults, the fields it checks (warned at compile time, refused by
  `Macaw.Auth.Ash.Config` at load), and its source, read and parsed at each
  sign-in (a fault raises before anything connects).
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Macaw.Auth.Ash.Config
  alias Macaw.Auth.Ash.Strategy.Ldap
  alias Macaw.Auth.Ash.Test.{Boot, Directory, MinimalLdapUser, User}

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

  # A strategy's field that isn't an attribute: the verifier's DSL error is
  # a compile warning (Spark's), so the resource compiles under default build
  # flags; Config refuses it at load, whatever they were. A disabled field
  # is the case that matters: left unchecked, a disabled user is let in.
  @tag verifies: "ash-ldap-fields"
  test "a disabled field that isn't an attribute: warned at compile time, refused at load" do
    {user, warnings} = compile_user("LdapUserWithoutDisabledField", :disabled_field, :locked_at)

    assert warnings =~ "authentication -> strategies -> corp -> disabled_field"
    assert warnings =~ ":locked_at is not an attribute of this resource"

    message =
      "config :macaw_auth, Macaw.Auth.Ash: strategy :corp's disabled_field: :locked_at " <>
        "is not an attribute of #{inspect(user)}"

    assert_raise ArgumentError, message, fn ->
      Config.parse!(user_resource: user, strategies: [:password, :corp])
    end

    # Checked whether or not the backend's strategies name it: AshAuthentication
    # can sign in through it all the same.
    assert_raise ArgumentError, message, fn -> Config.parse!(user_resource: user) end
  end

  @tag verifies: "ash-ldap-fields-boot"
  test "a user resource with a disabled field that isn't an attribute, configured: :macaw_auth refuses to start" do
    {user, _warnings} =
      compile_user("BootLdapUserWithoutDisabledField", :disabled_field, :locked_at)

    assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%ArgumentError{} = e, _}}}}}} =
             Boot.boot_with(user_resource: user)

    assert Exception.message(e) ==
             "config :macaw_auth, Macaw.Auth.Ash: strategy :corp's disabled_field: :locked_at " <>
               "is not an attribute of #{inspect(user)}"
  end

  # The fields the strategy's actions accept fail Ash's accept check when the
  # strategy builds those actions; a resource defining them itself leaves
  # the fields to the verifier's warning and Config's refusal, as above.
  @tag verifies: "ash-ldap-fields-accepted"
  test "the other field options: refused at load, or by Ash's accept check" do
    for {option, field} <- [
          identity_field: :login,
          roles_field: :groups,
          source_field: :owner,
          display_name_field: :nick
        ] do
      {user, warnings} =
        compile_user("LdapUserWithout_#{option}", option, field, own_actions: true)

      assert warnings =~ "authentication -> strategies -> corp -> #{option}"

      assert_raise ArgumentError,
                   "config :macaw_auth, Macaw.Auth.Ash: strategy :corp's #{option}: " <>
                     "#{inspect(field)} is not an attribute of #{inspect(user)}",
                   fn -> Config.parse!(user_resource: user, strategies: [:password, :corp]) end

      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_user("LdapUserBuiltWithout_#{option}", option, field)
        end

      assert error.message =~ "Cannot accept [#{inspect(field)}]"
    end
  end

  # A user resource with a password strategy and an LDAP strategy `corp`
  # whose `option` names `field`, the test app's token resource, and the
  # provision and refresh actions defined by the resource when `own_actions`.
  # Returns the module and what compiling it wrote to stderr.
  defp compile_user(name, option, field, opts \\ []) do
    module = Module.concat(Macaw.Auth.Ash.Test, name)

    actions =
      if opts[:own_actions] do
        """
        create :provision_with_corp do
          accept([:username, :roles, :source])
        end

        update :refresh_with_corp do
          accept([:roles])
        end
        """
      end

    source = """
    defmodule #{inspect(module)} do
      use Ash.Resource,
        domain: Macaw.Auth.Ash.Test.Elsewhere,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap]

      authentication do
        tokens do
          enabled?(true)
          token_resource(Macaw.Auth.Ash.Test.Token)
          require_token_presence_for_authentication?(true)
          token_lifetime({30, :days})
          signing_secret(fn _, _ -> {:ok, "macaw-auth-ash-test-signing-secret-of-some-length"} end)
        end

        strategies do
          password :password do
            identity_field(:username)
            hashed_password_field(:hashed_password)
          end

          ldap :corp do
            source({Macaw.Auth.Ash.Test.Directory, :nas, []})
            #{option}(#{inspect(field)})
          end
        end
      end

      attributes do
        uuid_primary_key(:id)
        attribute(:username, :string, allow_nil?: false, public?: true)
        attribute(:hashed_password, :string, sensitive?: true, public?: false)
        attribute(:roles, {:array, :string}, default: [], public?: true)
        attribute(:source, :string, public?: true)
      end

      identities do
        identity(:unique_username, [:username], pre_check_with: Macaw.Auth.Ash.Test.Elsewhere)
      end

      actions do
        defaults([:read])
        #{actions}
      end
    end
    """

    warnings = capture_io(:stderr, fn -> Code.compile_string(source) end)
    {module, warnings}
  end
end
