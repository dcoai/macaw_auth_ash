defmodule Macaw.Auth.Ash.Strategy.Ldap do
  @moduledoc """
  A directory sign-in as an AshAuthentication strategy: macaw_auth's
  `Macaw.Auth.Native.Source.Ldap` (its RFC 4514 and filter escaping, its
  TLS rules with `allow_plaintext: false`, its group checks and role
  mapping) on an Ash user resource, which it provisions at a user's first
  sign-in.

      defmodule MyApp.Accounts.User do
        use Ash.Resource,
          extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap], ...

        authentication do
          strategies do
            ldap :nas do
              source {MyApp.Directory, :nas, []}
              identity_field :username
              roles_field :roles
              source_field :source
              display_name_field :display_name
              disabled_field :disabled_at
            end
          end
        end
      end

  `source` is the directory's configuration, exactly as a native LDAP
  source's (`Macaw.Auth.Native.Source.Ldap.Config`, its `name` defaulting
  to the strategy's): a map, or `{module, function, args}` returning one,
  called at each sign-in. Prefer the function: a map in the resource is
  fixed when it compiles, and a host's directory and its service password
  belong to the runtime (`bind_password: {:env, "VAR"}` is resolved at
  sign-in either way). A configuration fault raises at sign-in, naming the
  key: it is a deployment bug, not a refusal.

  **The DSL entity builds** (unless the resource defines them already):

  - `sign_in_with_<name>`: a generic action taking `username` and
    `password`, returning the user. Through AshAuthentication (its plug, or
    `AshAuthentication.Strategy.action/4`) it signs a user token as the
    password strategy does; `Macaw.Auth.Ash` calls `sign_in/4` itself and
    makes its own session.
  - `provision_with_<name>`: a create accepting the identity, roles,
    source and display name fields.
  - `refresh_with_<name>`: an update accepting the roles and display name.

  **Provisioning** (as `Macaw.Auth.Native.Provision`): a directory user
  signing in for the first time gets a row, with `source_field` the
  directory's name and no password; at every later sign-in the
  directory's roles and display name replace the row's, so a user removed
  from an admin group loses the role at their next sign-in. A row with the
  username that another source owns (a local user, or another directory's)
  is never taken over (`:username_taken`), and a disabled row stays
  refused (`:disabled`), left as it is. The user resource needs a unique
  identity on `identity_field`: two first sign-ins at once then make one
  row.

  What the directory says beyond these (its DN, entry id, email) is not
  stored: a user resource has no standard place for it.
  """

  require Ash.Query
  import Ash.Expr, only: [ref: 1]

  alias AshAuthentication.Strategy.Custom.Helpers
  alias Macaw.Auth.Native.Source.Ldap, as: Source
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  defstruct [
    :name,
    :source,
    :display_name_field,
    :disabled_field,
    :sign_in_action_name,
    :provision_action_name,
    :refresh_action_name,
    :resource,
    :strategy_module,
    :__spark_metadata__,
    identity_field: :username,
    roles_field: :roles,
    source_field: :source
  ]

  @type t :: %__MODULE__{}

  @entity %Spark.Dsl.Entity{
    name: :ldap,
    describe: "Sign in against an LDAP directory, provisioning the user at first sign-in.",
    examples: [
      """
      ldap :nas do
        source {MyApp.Directory, :nas, []}
        identity_field :username
        roles_field :roles
        source_field :source
      end
      """
    ],
    target: __MODULE__,
    args: [{:optional, :name, :ldap}],
    schema: [
      name: [type: :atom, required: true, doc: "The strategy's name, and the source's."],
      source: [
        type: {:or, [:map, :mfa]},
        required: true,
        doc:
          "The directory's configuration (`Macaw.Auth.Native.Source.Ldap.Config`), or `{m, f, a}` returning it."
      ],
      identity_field: [
        type: :atom,
        default: :username,
        doc: "The attribute the directory's username goes in."
      ],
      roles_field: [
        type: :atom,
        default: :roles,
        doc: "The attribute (a list of strings) of roles."
      ],
      source_field: [
        type: :atom,
        default: :source,
        doc: "The attribute naming which source owns the row."
      ],
      display_name_field: [type: :atom, doc: "The attribute for the directory's display name."],
      disabled_field: [type: :atom, doc: "A boolean or timestamp attribute: set means refused."],
      sign_in_action_name: [type: :atom, doc: "Default `sign_in_with_<name>`."],
      provision_action_name: [type: :atom, doc: "Default `provision_with_<name>`."],
      refresh_action_name: [type: :atom, doc: "Default `refresh_with_<name>`."]
    ]
  }

  use AshAuthentication.Strategy.Custom, entity: @entity

  # ── Building the actions ────────────────────────────────────────────────

  @impl true
  def transform(strategy, dsl) do
    strategy = %{
      strategy
      | sign_in_action_name: strategy.sign_in_action_name || :"sign_in_with_#{strategy.name}",
        provision_action_name:
          strategy.provision_action_name || :"provision_with_#{strategy.name}",
        refresh_action_name: strategy.refresh_action_name || :"refresh_with_#{strategy.name}"
    }

    display = List.wrap(strategy.display_name_field)

    with {:ok, dsl} <-
           maybe_add(dsl, strategy.provision_action_name, :create,
             accept:
               [strategy.identity_field, strategy.roles_field, strategy.source_field] ++ display
           ),
         {:ok, dsl} <-
           maybe_add(dsl, strategy.refresh_action_name, :update,
             accept: [strategy.roles_field] ++ display
           ),
         {:ok, dsl} <- maybe_add(dsl, strategy.sign_in_action_name, :action, sign_in(dsl)) do
      {:ok,
       dsl
       |> then(&Helpers.register_strategy_actions([strategy.sign_in_action_name], &1, strategy))
       |> Helpers.put_strategy(strategy)}
    end
  end

  defp sign_in(dsl) do
    argument = fn name, sensitive? ->
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :argument,
        name: name,
        type: :string,
        allow_nil?: false,
        sensitive?: sensitive?,
        public?: true
      )
    end

    [
      arguments: [argument.(:username, false), argument.(:password, true)],
      returns: :struct,
      constraints: [instance_of: Transformer.get_persisted(dsl, :module)],
      run: {Macaw.Auth.Ash.Strategy.Ldap.SignIn, []}
    ]
  end

  defp maybe_add(dsl, name, type, opts) do
    if Ash.Resource.Info.action(dsl, name) do
      {:ok, dsl}
    else
      with {:ok, action} <-
             Transformer.build_entity(Ash.Resource.Dsl, [:actions], type, [name: name] ++ opts) do
        {:ok, Transformer.add_entity(dsl, [:actions], action)}
      end
    end
  end

  @impl true
  def verify(strategy, dsl) do
    fields =
      [
        identity_field: strategy.identity_field,
        roles_field: strategy.roles_field,
        source_field: strategy.source_field,
        display_name_field: strategy.display_name_field,
        disabled_field: strategy.disabled_field
      ]
      |> Enum.reject(fn {_key, name} -> is_nil(name) end)

    case Enum.find(fields, fn {_key, name} -> !Ash.Resource.Info.attribute(dsl, name) end) do
      nil ->
        :ok

      {key, name} ->
        {:error,
         DslError.exception(
           module: Transformer.get_persisted(dsl, :module),
           path: [:authentication, :strategies, strategy.name, key],
           message: "#{inspect(name)} is not an attribute of this resource"
         )}
    end
  end

  # ── Signing in ──────────────────────────────────────────────────────────

  @doc """
  Checks a password against the directory and provisions the user:
  `{:ok, record}`, or `{:error, reason, knows?}`, where `knows?` says
  whether the refusal is final (`Macaw.Auth.Native.Source.Ldap.knows?/2`;
  a provisioning refusal always is). `reason` is the source's
  (`explain_refusal/1`), or `:username_taken` or
  `:disabled`: for logs, never for the visitor.
  """
  @spec sign_in(t(), String.t(), String.t(), keyword()) ::
          {:ok, Ash.Resource.record()} | {:error, atom(), boolean()}
  def sign_in(%__MODULE__{} = strategy, username, password, _opts) do
    source = source!(strategy)

    case Source.authenticate(source, username, password, []) do
      {:ok, attrs} ->
        case provision(strategy, source.name, attrs, true) do
          {:ok, record} -> {:ok, record}
          {:error, reason} -> {:error, reason, true}
        end

      {:error, reason} ->
        {:error, reason, Source.knows?(source, reason)}
    end
  end

  @doc "A sentence explaining a refusal's reason, for logs and diagnostics."
  @spec explain_refusal(atom()) :: String.t()
  def explain_refusal(:username_taken), do: "a user with that username belongs to another source"
  def explain_refusal(:disabled), do: "the user is disabled"
  def explain_refusal(reason), do: Source.explain(reason)

  @doc "The directory's configuration, parsed: raises `ArgumentError` naming a fault."
  @spec source!(t()) :: Source.t()
  def source!(%__MODULE__{source: source} = strategy) do
    config =
      case source do
        {m, f, a} -> apply(m, f, a)
        map -> map
      end
      |> Map.new()
      |> Map.put(:type, :ldap)
      |> Map.put_new(:name, to_string(strategy.name))

    case Source.parse(config, []) do
      {:ok, parsed} -> parsed
      {:error, message} -> raise ArgumentError, "LDAP strategy #{strategy.name}: #{message}"
    end
  end

  defp provision(strategy, name, attrs, retry) do
    case by_identity(strategy, attrs.username) do
      nil ->
        create(strategy, name, attrs, retry)

      record ->
        cond do
          Map.get(record, strategy.source_field) != name -> {:error, :username_taken}
          disabled?(strategy, record) -> {:error, :disabled}
          true -> refresh(strategy, record, attrs)
        end
    end
  end

  defp by_identity(strategy, username) do
    identity = strategy.identity_field

    strategy.resource
    |> Ash.Query.filter(^ref(identity) == ^username)
    |> Ash.read_one!(ash(strategy))
  end

  defp create(strategy, name, attrs, retry) do
    params =
      %{
        strategy.identity_field => attrs.username,
        strategy.roles_field => attrs.roles,
        strategy.source_field => name
      }
      |> display_name(strategy, attrs)

    strategy.resource
    |> Ash.Changeset.for_create(strategy.provision_action_name, params, ash(strategy))
    |> Ash.create()
    |> case do
      {:ok, record} ->
        {:ok, record}

      # Two first sign-ins at once: the other made the row, so use it.
      # Anything else is a bug in the resource, raised.
      {:error, error} ->
        if retry and by_identity(strategy, attrs.username),
          do: provision(strategy, name, attrs, false),
          else: raise(error)
    end
  end

  defp refresh(strategy, record, attrs) do
    params = display_name(%{strategy.roles_field => attrs.roles}, strategy, attrs)

    {:ok,
     record
     |> Ash.Changeset.for_update(strategy.refresh_action_name, params, ash(strategy))
     |> Ash.update!()}
  end

  defp display_name(params, %{display_name_field: nil}, _attrs), do: params

  defp display_name(params, %{display_name_field: field}, attrs),
    do: Map.put(params, field, attrs[:display_name])

  defp disabled?(%{disabled_field: nil}, _record), do: false
  defp disabled?(%{disabled_field: field}, record), do: Map.get(record, field) not in [nil, false]

  defp ash(strategy),
    do: [domain: AshAuthentication.Info.domain!(strategy.resource), authorize?: false]
end
