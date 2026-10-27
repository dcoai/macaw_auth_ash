defmodule Macaw.Auth.Ash do
  @moduledoc """
  A `Macaw.Auth` backend over AshAuthentication: a host's Ash user and
  token resources behind the contract, so an Ash host gets Macaw's plugs,
  LiveView hooks, steps and revocation push without a second user table.

      config :macaw_auth, backend: Macaw.Auth.Ash
      config :macaw_auth, Macaw.Auth.Ash,
        user_resource: MyApp.Accounts.User,
        strategies: [:password],
        roles_from: :roles,
        disabled_field: :disabled_at

  (`Macaw.Auth.Ash.Config` has every key.) The token resource takes
  `Macaw.Auth.Ash.TokenResource` and `Macaw.Auth.Ash.Notifier`; a
  directory sign-in is the `Macaw.Auth.Ash.Strategy.Ldap` strategy on the
  user resource.

  - **Who someone is**: `authenticate/2` runs the configured
    AshAuthentication strategies in order, as `Macaw.Auth.Native` runs its
    sources: the first that knows the user decides; failures back off by
    macaw_auth's native throttle.
  - **Their sessions**: stored user tokens in the token resource
    (`Macaw.Auth.Ash.Sessions`, which says why).

  **The second factor is unsupported.** AshAuthentication 4.x, the stable
  line this backend targets, has no TOTP strategy (5.0, a release
  candidate as this is written, adds one). So every user reports
  `second_factor: :none`, no session owes the step, and
  `verify_second_factor/3` refuses with `{:error, :unsupported}`. The
  conformance kit runs with its second-factor block pending, saying why,
  rather than passed by a stub. A host that needs a second factor today
  uses `Macaw.Auth.Native`.
  """

  @behaviour Macaw.Auth.Backend

  require Ash.Query
  import Ash.Expr, only: [ref: 1]

  alias AshAuthentication.Strategy.Password
  alias Macaw.Auth.Ash.{Config, Sessions}
  alias Macaw.Auth.Ash.Strategy.Ldap
  alias Macaw.Auth.Native.Throttle
  alias Macaw.Auth.User

  @doc """
  Checks `%{username: _, password: _}` against the configured strategies,
  in order: `{:ok, %Macaw.Auth.User{}}`, or `{:error, :invalid_credentials
  | :disabled | :throttled}`. Options: `:remote_ip` (a string or an
  address tuple; the client's, for the throttle's address key), `:now` (a
  `DateTime`, for the throttle's clock).

  **The first strategy that knows the user decides.** A password
  strategy knows a user who has a row with a password hash; an LDAP
  strategy, one its directory knows (`Macaw.Auth.Native.Source.Ldap.knows?/2`).
  A refusal by a strategy that knows the user is final: a wrong password
  never falls through to the next strategy, or one account's password
  could be tried against another's. One that doesn't passes the attempt
  on.

  **One refusal.** A wrong password and an unknown user are both
  `:invalid_credentials`, and take the same time: AshAuthentication's
  password sign-in hashes against nothing when no user matches
  (`hash_provider.simulate/0`, bcrypt's `no_user_verify`), as for a wrong
  password it hashes against the user's; an empty username or password,
  which never reaches the sign-in query, is hashed against nothing here.
  A disabled user (`disabled_field`) is refused with `:disabled`, only
  after the right password, so the refusal tells a guesser nothing.

  **Throttled** as the native backend is, by its throttle
  (`Macaw.Auth.Native.Throttle`, which macaw_auth's application starts
  whichever backend is configured): failures back off per username
  (trimmed and case-folded; an empty one shares one key) and per
  `:remote_ip`. While either waits, the attempt is refused `:throttled`
  without checking the password, and not counted, but a hash's time is
  still spent (as for an empty field), so the response time doesn't tell
  a guesser when the block starts or ends. Every other refusal counts as
  a failure; a success resets the username's count, never the address's.

  Emits `[:macaw_auth, :ash, :authenticate]` with `%{count: 1}` and
  `%{result: :ok | :error, reason: term, strategy: name | nil, user_id:
  id | nil}`; never the username or password.
  """
  @impl Macaw.Auth.Backend
  @spec authenticate(map(), keyword()) ::
          {:ok, User.t()} | {:error, :invalid_credentials | :disabled | :throttled}
  def authenticate(credentials, opts \\ []) do
    config = Config.get()
    username = credentials[:username] |> text() |> String.trim()
    password = text(credentials[:password])
    key = throttle_key(username)
    ip = address(Keyword.get(opts, :remote_ip))
    now = clock(opts)

    case Throttle.check(key, ip, now) do
      {:delay, _ms} ->
        simulate(config)
        event(:error, :throttled, nil, nil)
        {:error, :throttled}

      :ok ->
        result = check(config, username, password)

        case result do
          {:ok, _user} -> Throttle.success(key)
          {:error, _reason} -> Throttle.failure(key, ip, now)
        end

        result
    end
  end

  defp check(config, username, password) do
    if username == "" or password == "" do
      simulate(config)
      event(:error, :empty, nil, nil)
      {:error, :invalid_credentials}
    else
      case chain(config, username, password) do
        {:ok, record, strategy} ->
          user = to_user(record, config)

          if user.disabled do
            event(:error, :disabled, strategy, user.id)
            {:error, :disabled}
          else
            event(:ok, nil, strategy, user.id)
            {:ok, user}
          end

        {:error, reason, strategy} ->
          event(:error, reason, strategy, nil)
          {:error, if(reason == :disabled, do: :disabled, else: :invalid_credentials)}
      end
    end
  end

  defp text(value) when is_binary(value), do: value
  defp text(_), do: ""

  # One count for `Alice`, ` alice` and `ALICE`; every empty username
  # shares the one key it can never sign in with.
  defp throttle_key(""), do: :invalid
  defp throttle_key(username), do: String.downcase(username)

  defp address(nil), do: nil
  defp address(ip) when is_binary(ip), do: ip
  defp address(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> to_string()

  defp clock(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = now -> DateTime.to_unix(now, :millisecond)
      nil -> Throttle.now()
    end
  end

  defp chain(config, username, password) do
    Enum.reduce_while(config.strategies, {:error, :invalid_credentials, nil}, fn strategy, _ ->
      case sign_in(config, strategy, username, password) do
        {:ok, record} -> {:halt, {:ok, record, strategy}}
        {:error, reason, true} -> {:halt, {:error, reason, strategy}}
        {:error, reason, false} -> {:cont, {:error, reason, strategy}}
      end
    end)
  end

  # `{:ok, record}` or `{:error, reason, knows?}`.
  #
  # AshAuthentication 4.15's password sign-in always signs a user token for
  # the user it accepts (its preparation has no way to ask for none). The
  # session is create_session's, so that token is revoked at once, quietly
  # (`Macaw.Auth.Ash.Notifier` ignores it): it never leaves this function,
  # and revoked it is no credential even to AshAuthentication.
  defp sign_in(config, %Password{} = strategy, username, password) do
    params = %{
      to_string(strategy.identity_field) => username,
      to_string(strategy.password_field) => password
    }

    case AshAuthentication.Strategy.action(strategy, :sign_in, params, domain: config.domain) do
      {:ok, record} ->
        discard_token(config, record.__metadata__[:token])
        {:ok, record}

      {:error, _} ->
        {:error, :invalid_credentials, has_password?(config, strategy, username)}
    end
  end

  defp sign_in(_config, %Ldap{} = strategy, username, password),
    do: Ldap.sign_in(strategy, username, password, [])

  defp discard_token(_config, nil), do: :ok

  defp discard_token(config, token) do
    :ok =
      AshAuthentication.TokenResource.Actions.revoke(config.token_resource, token,
        context: Macaw.Auth.Ash.Notifier.quiet()
      )
  end

  defp has_password?(config, strategy, username) do
    identity = strategy.identity_field
    hashed = strategy.hashed_password_field

    config.user_resource
    |> Ash.Query.filter(^ref(identity) == ^username and not is_nil(^ref(hashed)))
    |> Ash.exists?(domain: config.domain, authorize?: false)
  end

  # A hash's time spent against nothing, as the password strategy does for
  # an unknown user.
  defp simulate(config) do
    case Enum.find(config.strategies, &match?(%Password{}, &1)) do
      %Password{hash_provider: provider} -> provider.simulate()
      nil -> :ok
    end
  end

  defp event(result, reason, strategy, user_id) do
    :telemetry.execute([:macaw_auth, :ash, :authenticate], %{count: 1}, %{
      result: result,
      reason: reason,
      strategy: strategy && strategy.name,
      user_id: user_id
    })
  end

  @doc """
  A user record as the contract's `%Macaw.Auth.User{}`: the username from
  `username_field`, roles from `roles_from`, the source from
  `source_field` (else `"local"`), disabled from `disabled_field` (true,
  or any timestamp), and no second factor (see the moduledoc).
  """
  @spec to_user(struct(), Config.t()) :: User.t()
  def to_user(record, %Config{} = config \\ Config.get()) do
    %User{
      id: Map.fetch!(record, config.primary_key),
      username: to_string(Map.fetch!(record, config.username_field)),
      display_name: field(record, config.display_name_field),
      source: field(record, config.source_field) || "local",
      roles: roles(record, config.roles_from),
      disabled: disabled?(field(record, config.disabled_field)),
      second_factor: :none
    }
  end

  defp field(_record, nil), do: nil
  defp field(record, name), do: Map.get(record, name)

  defp roles(record, {m, f}), do: apply(m, f, [record]) || []
  defp roles(record, name), do: Map.get(record, name) || []

  defp disabled?(nil), do: false
  defp disabled?(false), do: false
  defp disabled?(_set), do: true

  @impl Macaw.Auth.Backend
  defdelegate create_session(user, opts), to: Sessions, as: :create

  @impl Macaw.Auth.Backend
  defdelegate fetch_session(token, opts), to: Sessions, as: :fetch

  @impl Macaw.Auth.Backend
  defdelegate fetch_session_by_id(id, opts), to: Sessions, as: :fetch_by_id

  @doc """
  The idle limit `fetch_session/2` expires sessions by: `idle_days` in
  seconds, which is also the remember cookie's lifetime.
  """
  @impl Macaw.Auth.Backend
  @spec session_idle_seconds(keyword()) :: pos_integer()
  def session_idle_seconds(_opts), do: Config.get().idle_days * 86_400

  @doc """
  Checks the whole configuration (`Macaw.Auth.Ash.Config.get/0`: the
  resources, the strategies and every LDAP strategy's fields, the
  notifier, `idle_days` against the token lifetime): `:ok`, or
  `ArgumentError` naming the fault. macaw_auth's application calls it at
  start, so a misconfigured host refuses boot rather than failing its
  first sign-in.
  """
  @impl Macaw.Auth.Backend
  @spec check_config!() :: :ok
  def check_config! do
    %Config{} = Config.get()
    :ok
  end

  @impl Macaw.Auth.Backend
  defdelegate list_sessions(user_id, opts), to: Sessions, as: :list

  @impl Macaw.Auth.Backend
  defdelegate revoke_sessions(target, opts), to: Sessions, as: :revoke

  @impl Macaw.Auth.Backend
  defdelegate complete_step(session_id, step, opts), to: Sessions

  @doc """
  Unsupported: `{:error, :unsupported}`. AshAuthentication 4.x has no TOTP
  strategy; users never owe a second factor under this backend (see the
  moduledoc).
  """
  @impl Macaw.Auth.Backend
  def verify_second_factor(_session_id, _code, _opts), do: {:error, :unsupported}
end
