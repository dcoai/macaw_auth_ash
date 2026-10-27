defmodule Macaw.Auth.Ash.Config do
  @moduledoc """
  `Macaw.Auth.Ash`'s configuration, read from the application environment
  and checked, so a fault names its key rather than failing a sign-in
  somewhere deeper:

      config :macaw_auth, Macaw.Auth.Ash,
        user_resource: MyApp.Accounts.User,
        token_resource: MyApp.Accounts.Token,   # default: the user resource's
        domain: MyApp.Accounts,                 # default: the user resource's
        strategies: [:password, :nas],          # or strategy: :password
        roles_from: :roles,                     # or {MyApp.Accounts, :roles_of}
        username_field: :email,                 # default: the first strategy's identity field
        display_name_field: :name,              # optional
        source_field: :source,                  # optional; without it every user is "local"
        disabled_field: :disabled_at,           # optional, boolean or timestamp
        idle_days: 14

  - `strategies` are AshAuthentication strategy names on the user
    resource, tried in order as `Macaw.Auth.Native`'s sources are: the
    first that knows the user decides (`Macaw.Auth.Ash.authenticate/2`).
    Each is a password strategy or a `Macaw.Auth.Ash.Strategy.Ldap`.
  - `roles_from` is an attribute holding a list of strings, or `{m, f}`
    called with the user record.
  - `idle_days`: a session unused this long expires.

  Read on every call (`get/0`), not cached: it is a handful of keyword
  lookups, and a test or a host that changes it sees the change at once.
  A fault raises `ArgumentError`: it is a deployment bug, not a refusal.
  """

  @enforce_keys [:user_resource, :token_resource, :domain, :strategies, :primary_key]
  defstruct [
    :user_resource,
    :token_resource,
    :domain,
    :strategies,
    :primary_key,
    :username_field,
    :display_name_field,
    :source_field,
    :disabled_field,
    roles_from: :roles,
    idle_days: 14
  ]

  @type t :: %__MODULE__{
          user_resource: module(),
          token_resource: module(),
          domain: module(),
          strategies: [struct()],
          primary_key: atom(),
          username_field: atom(),
          display_name_field: atom() | nil,
          source_field: atom() | nil,
          disabled_field: atom() | nil,
          roles_from: atom() | {module(), atom()},
          idle_days: pos_integer()
        }

  @keys ~w(user_resource token_resource domain strategy strategies roles_from username_field
           display_name_field source_field disabled_field idle_days)a

  @doc "The configuration, checked; raises `ArgumentError` naming a fault."
  @spec get() :: t()
  def get, do: parse!(Application.get_env(:macaw_auth, Macaw.Auth.Ash, []))

  @doc "Checks `settings` (a keyword list) as `get/0` does."
  @spec parse!(keyword()) :: t()
  def parse!(settings) do
    unknown = Keyword.keys(settings) -- @keys
    if unknown != [], do: fail("unknown keys #{inspect(unknown)}")

    user = Keyword.get(settings, :user_resource) || fail("user_resource is required")
    resource!(user, :user_resource)

    token =
      Keyword.get_lazy(settings, :token_resource, fn ->
        case AshAuthentication.Info.authentication_tokens_token_resource(user) do
          {:ok, token} -> token
          :error -> fail("token_resource is required (#{inspect(user)} names none)")
        end
      end)

    resource!(token, :token_resource)

    unless Spark.Dsl.Extension.get_persisted(token, :macaw_auth_ash_token?, false),
      do:
        fail("token_resource #{inspect(token)} needs the Macaw.Auth.Ash.TokenResource extension")

    domain = Keyword.get_lazy(settings, :domain, fn -> Ash.Resource.Info.domain(user) end)
    strategies = strategies!(user, settings)

    %__MODULE__{
      user_resource: user,
      token_resource: token,
      domain: domain,
      strategies: strategies,
      primary_key: primary_key!(user),
      username_field:
        attribute!(
          user,
          :username_field,
          Keyword.get(settings, :username_field, hd(strategies).identity_field)
        ),
      display_name_field: optional_attribute!(user, settings, :display_name_field),
      source_field: optional_attribute!(user, settings, :source_field),
      disabled_field: optional_attribute!(user, settings, :disabled_field),
      roles_from: roles_from!(user, Keyword.get(settings, :roles_from, :roles)),
      idle_days: idle_days!(Keyword.get(settings, :idle_days, 14))
    }
  end

  defp resource!(module, key) do
    unless is_atom(module) and Ash.Resource.Info.resource?(module),
      do: fail("#{key}: #{inspect(module)} is not an Ash resource")
  end

  defp strategies!(user, settings) do
    names =
      case {Keyword.get(settings, :strategies), Keyword.get(settings, :strategy)} do
        {nil, nil} -> [:password]
        {nil, name} -> [name]
        {names, nil} when is_list(names) and names != [] -> names
        _ -> fail("set one of strategy (a name) or strategies (a non-empty list)")
      end

    Enum.map(names, fn name ->
      case AshAuthentication.Info.strategy(user, name) do
        {:ok, %AshAuthentication.Strategy.Password{} = s} -> s
        {:ok, %Macaw.Auth.Ash.Strategy.Ldap{} = s} -> s
        {:ok, other} -> fail("strategy #{inspect(name)} is a #{inspect(other.__struct__)}")
        :error -> fail("strategy #{inspect(name)} is not on #{inspect(user)}")
      end
    end)
  end

  # Sessions name their user by the subject's one primary key value.
  defp primary_key!(user) do
    case Ash.Resource.Info.primary_key(user) do
      [key] -> key
      keys -> fail("user_resource needs a single-attribute primary key, not #{inspect(keys)}")
    end
  end

  defp optional_attribute!(user, settings, key) do
    case Keyword.get(settings, key) do
      nil -> nil
      name -> attribute!(user, key, name)
    end
  end

  defp attribute!(user, key, name) do
    if is_atom(name) and Ash.Resource.Info.attribute(user, name),
      do: name,
      else: fail("#{key}: #{inspect(name)} is not an attribute of #{inspect(user)}")
  end

  defp roles_from!(user, name) when is_atom(name), do: attribute!(user, :roles_from, name)

  defp roles_from!(_user, {m, f} = mf) when is_atom(m) and is_atom(f) do
    Code.ensure_loaded(m)

    if function_exported?(m, f, 1),
      do: mf,
      else: fail("roles_from: #{inspect(m)}.#{f}/1 is not defined")
  end

  defp roles_from!(_user, other),
    do: fail("roles_from: #{inspect(other)} is neither an attribute nor {module, function}")

  defp idle_days!(days) when is_integer(days) and days > 0, do: days
  defp idle_days!(other), do: fail("idle_days: #{inspect(other)} is not a positive integer")

  defp fail(message), do: raise(ArgumentError, "config :macaw_auth, Macaw.Auth.Ash: " <> message)
end
