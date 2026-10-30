defmodule Macaw.Auth.Ash.Sessions do
  @moduledoc """
  `Macaw.Auth.Ash`'s sessions, kept in the host's AshAuthentication token
  resource.

  **A session is a stored user token.** `create/2` signs an ordinary
  AshAuthentication user JWT for the user (`AshAuthentication.Jwt`, the
  resource's own secret, lifetime and claims) and stores its row: the
  `jti`, purpose `"user"`, subject and expiry, and Macaw's metadata in
  `extra_data["macaw_auth"]` (when it was made and last used, the client's
  address and agent, the second factor, the steps done). The JWT goes to
  the client; the session's id is its `jti`.

  Why the token resource rather than a session table of our own: it is
  where an Ash host already keeps tokens, so one revocation means the same
  to AshAuthentication's plugs and to Macaw (a revoked session is a token
  AshAuthentication refuses too, and a token AshAuthentication revokes is a
  session Macaw refuses), its expunger clears the rows, and the host has no
  second table to migrate. What it lacked, an update of `extra_data` and a
  revocation by jti that keeps the row's expiry, `Macaw.Auth.Ash.TokenResource`
  adds.

  The contract's guarantees, and how:

  - **No token stored.** The row holds the `jti`, a random value inside
    the JWT's signed payload, never the JWT; a `jti` alone signs nobody in,
    since a token must carry the resource's signature. The kit checks
    every stored value against the tokens it was given.
  - **Revocation.** Revoking sets the row's purpose to `"revocation"`
    (`:macaw_auth_revoke`), the state AshAuthentication's own
    `revoked?` check looks for; the row keeps its expiry, so the expunger
    removes it when the JWT could no longer verify anyway. A session is
    valid only while its row has purpose `"user"` and Macaw's metadata, so
    a token AshAuthentication minted for itself is not a Macaw session.
  - **Idle expiry slides.** A session unused for `idle_days` expires and is
    revoked at its next look-up; a request (`touch: true`) records use at
    most once an hour, and a re-check (`touch: false`) never does. The
    JWT's own expiry (the user resource's `token_lifetime`) is the
    session's absolute limit, at least `idle_days` (`Macaw.Auth.Ash.Config`
    refuses a shorter one).
  - **A deleted user has no new session.** `create/2` for a user deleted
    after signing in is `{:error, :invalid}`.
  - **A disabled user has no session.** Looking one up revokes it.

  Every function honors `:now`. Every read and write is made with
  `authorize?: false`: this is the authentication layer itself, before
  there is an actor to authorize.
  """

  require Ash.Query

  alias AshAuthentication.Jwt
  alias Macaw.Auth.Ash.{Config, TokenResource}
  alias Macaw.Auth.{Session, User}

  @touch_every 3_600
  @user_agent_max 255
  @key "macaw_auth"

  @doc """
  Starts a session for `user`: `{:ok, token, session}`, the JWT for the
  client only, or `{:error, :invalid}` when the user is gone (deleted
  after signing in): there is no record to sign a token for, and nothing
  is stored. Options: `:remote_ip`, `:user_agent`,
  `:second_factor_passed` (default true), `:now`.
  """
  @spec create(User.t(), keyword()) :: {:ok, binary(), Session.t()} | {:error, :invalid}
  def create(%User{} = user, opts) do
    config = Config.get()

    case Ash.get(config.user_resource, user.id, ash(config) ++ [not_found_error?: false]) do
      {:ok, nil} -> {:error, :invalid}
      {:ok, record} -> start(config, user, record, opts)
    end
  end

  defp start(config, user, record, opts) do
    now = now(opts)
    {:ok, token, %{"jti" => jti}} = Jwt.token_for_user(record, %{"purpose" => "user"})

    meta = %{
      "created_at" => DateTime.to_iso8601(now),
      "last_used_at" => DateTime.to_iso8601(now),
      "remote_ip" => ip(Keyword.get(opts, :remote_ip)),
      "user_agent" => truncate(Keyword.get(opts, :user_agent)),
      "second_factor_passed" => Keyword.get(opts, :second_factor_passed, true),
      "completed_steps" => []
    }

    # Stored here even when the resource stores every token itself
    # (`store_all_tokens?`): the upsert adds Macaw's metadata to that row.
    :ok =
      AshAuthentication.TokenResource.Actions.store_token(
        config.token_resource,
        %{"token" => token, "purpose" => "user", "extra_data" => %{@key => meta}},
        domain: config.domain,
        authorize?: false
      )

    {:ok, token, to_session(jti, user.id, meta)}
  end

  defp ip(nil), do: nil
  defp ip(ip) when is_binary(ip), do: ip
  defp ip(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> to_string()

  defp truncate(agent) when is_binary(agent), do: String.slice(agent, 0, @user_agent_max)
  defp truncate(_), do: nil

  # Three base64url segments: anything else is no JWT, and is refused
  # before it reaches the JWT library.
  @jwt ~r/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/

  @doc """
  Resolves a token: its signature and claims verified against the user
  resource, then its session. `{:ok, user, session}` or `{:error, :invalid
  | :expired | :disabled}`. Options: `:touch` (default false), `:now`.
  """
  @spec fetch(binary(), keyword()) ::
          {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}
  def fetch(token, opts) when is_binary(token) do
    config = Config.get()

    with true <- String.valid?(token) and token =~ @jwt,
         {:ok, %{"jti" => jti, "sub" => subject}, _resource} <-
           Jwt.verify(token, config.user_resource) do
      validate(config, row(config, jti), subject, opts)
    else
      _ -> {:error, :invalid}
    end
  end

  def fetch(_token, _opts), do: {:error, :invalid}

  @doc "As `fetch/2`, by session id (the token's `jti`): what an open page re-checks with."
  @spec fetch_by_id(term(), keyword()) ::
          {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}
  def fetch_by_id(id, opts) when is_binary(id) do
    config = Config.get()

    case row(config, id) do
      nil -> {:error, :invalid}
      row -> validate(config, row, row.subject, opts)
    end
  end

  def fetch_by_id(_id, _opts), do: {:error, :invalid}

  defp row(config, jti) do
    config
    |> query()
    |> Ash.Query.filter(jti == ^jti and purpose == "user")
    |> Ash.read_one!(ash(config))
    |> then(&if(&1 && meta(&1), do: &1))
  end

  defp meta(%{extra_data: %{@key => %{} = meta}}), do: meta
  defp meta(_row), do: nil

  defp validate(_config, nil, _subject, _opts), do: {:error, :invalid}

  # The row must be the token's: a jti is random, but the subject is checked
  # as well, so a row can only ever stand for the token that made it.
  defp validate(_config, %{subject: stored}, subject, _opts) when stored != subject,
    do: {:error, :invalid}

  defp validate(config, row, subject, opts) do
    now = now(opts)
    meta = meta(row)
    idle = DateTime.diff(now, timestamp(meta["last_used_at"]))

    case AshAuthentication.subject_to_user(subject, config.user_resource, ash(config)) do
      {:error, _} ->
        {:error, :invalid}

      {:ok, record} ->
        user = Macaw.Auth.Ash.to_user(record, config)

        cond do
          user.disabled ->
            revoke_rows(config, [row.jti])
            {:error, :disabled}

          idle > config.idle_days * 86_400 or DateTime.compare(row.expires_at, now) != :gt ->
            revoke_rows(config, [row.jti])
            {:error, :expired}

          Keyword.get(opts, :touch, false) and idle >= @touch_every ->
            meta = Map.put(meta, "last_used_at", DateTime.to_iso8601(now))

            with :ok <- update_meta(config, row, meta),
                 do: {:ok, user, to_session(row.jti, user.id, meta)}

          true ->
            {:ok, user, to_session(row.jti, user.id, meta)}
        end
    end
  end

  # Only a live session's row: a revocation racing this write wins, and
  # the write is then `{:error, :invalid}`, the row left revoked.
  defp update_meta(config, row, meta) do
    extra = Map.put(row.extra_data || %{}, @key, meta)

    config
    |> query()
    |> Ash.Query.filter(jti == ^row.jti and purpose == "user")
    |> Ash.bulk_update!(
      TokenResource.update_action(),
      %{extra_data: extra},
      ash(config) ++ [return_records?: true, strategy: [:atomic, :atomic_batches, :stream]]
    )
    |> Map.fetch!(:records)
    |> case do
      [_row] -> :ok
      [] -> {:error, :invalid}
    end
  end

  @doc "A user's sessions, newest first (created at, then id: timestamps can tie)."
  @spec list(term(), keyword()) :: [Session.t()]
  def list(user_id, _opts) do
    config = Config.get()

    config
    |> rows_of(user_id)
    |> Enum.map(&to_session(&1.jti, user_id, meta(&1)))
    |> Enum.sort_by(&{DateTime.to_unix(&1.created_at, :microsecond), &1.id}, :desc)
  end

  defp rows_of(config, user_id) do
    subject = subject(config, user_id)

    config
    |> query()
    |> Ash.Query.filter(subject == ^subject and purpose == "user")
    |> Ash.read!(ash(config))
    |> Enum.filter(&meta/1)
  end

  @doc """
  Revokes one session (an id) or a user's (`{:user, id}`, keeping
  `:except`): `{user_id, ids}`, the ids empty when nothing was there.
  """
  @spec revoke(term(), keyword()) :: {term(), [term()]}
  def revoke({:user, user_id}, opts) do
    config = Config.get()
    except = Keyword.get(opts, :except)
    ids = for row <- rows_of(config, user_id), row.jti != except, do: row.jti
    {user_id, Enum.map(revoke_rows(config, ids), & &1.jti)}
  end

  def revoke(id, _opts) when is_binary(id) do
    config = Config.get()

    case revoke_rows(config, [id]) do
      [row] ->
        case subject_user_id(row.subject, config.user_resource) do
          {:ok, user_id} -> {user_id, [id]}
          :error -> {nil, [id]}
        end

      [] ->
        {nil, []}
    end
  end

  def revoke(_id, _opts), do: {nil, []}

  # Flips live rows to revocations, returning those it flipped: a row
  # revoked twice at once is counted by one of the two.
  defp revoke_rows(_config, []), do: []

  defp revoke_rows(config, ids) do
    config
    |> query()
    |> Ash.Query.filter(jti in ^ids and purpose == "user")
    |> Ash.bulk_update!(
      TokenResource.revoke_action(),
      %{},
      ash(config) ++
        [return_records?: true, strategy: [:atomic, :atomic_batches, :stream]]
    )
    |> Map.fetch!(:records)
  end

  @doc """
  Records a step on a session: the second factor, or another step done.
  `:ok`, or `{:error, :invalid}` when there is no live session by that id
  (revoked, by Macaw or AshAuthentication, even between this read and its
  write; or never one), which is left as it is.
  """
  @spec complete_step(term(), Macaw.Auth.step(), keyword()) :: :ok | {:error, :invalid}
  def complete_step(id, step, _opts) when is_binary(id) do
    config = Config.get()

    case row(config, id) do
      nil ->
        {:error, :invalid}

      row ->
        meta = meta(row)

        meta =
          if step in [:second_factor, :second_factor_enroll],
            do: Map.put(meta, "second_factor_passed", true),
            else:
              Map.update(meta, "completed_steps", [to_string(step)], fn steps ->
                Enum.uniq([to_string(step) | steps])
              end)

        update_meta(config, row, meta)
    end
  end

  def complete_step(_id, _step, _opts), do: {:error, :invalid}

  @doc """
  The user id a token's subject names (the primary key's value, as the
  subject carries it), or `:error` for another resource's subject.
  """
  @spec subject_user_id(String.t(), module()) :: {:ok, String.t()} | :error
  def subject_user_id(subject, user_resource) do
    case AshAuthentication.subject_to_primary_key(subject, user_resource) do
      {:ok, [{_key, value}]} -> {:ok, value}
      _ -> :error
    end
  end

  # AshAuthentication's own subject, made from a record carrying only the id,
  # so a deleted user's sessions can still be found.
  defp subject(config, user_id),
    do:
      AshAuthentication.user_to_subject(
        struct(config.user_resource, [{config.primary_key, user_id}])
      )

  defp to_session(jti, user_id, meta) do
    %Session{
      id: jti,
      user_id: user_id,
      created_at: timestamp(meta["created_at"]),
      last_used_at: timestamp(meta["last_used_at"]),
      remote_ip: meta["remote_ip"],
      user_agent: meta["user_agent"],
      second_factor_passed: meta["second_factor_passed"] == true,
      completed_steps: steps(meta["completed_steps"])
    }
  end

  # Steps come back as strings; only the contract's own become atoms.
  defp steps(names) when is_list(names),
    do: for(step <- Macaw.Auth.steps(), to_string(step) in names, do: step)

  defp steps(_), do: []

  defp timestamp(iso) do
    {:ok, at, _offset} = DateTime.from_iso8601(iso)
    at
  end

  defp query(config),
    do: Ash.Query.for_read(config.token_resource, TokenResource.read_action(), %{}, ash(config))

  defp now(opts), do: Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

  defp ash(config), do: [domain: config.domain, authorize?: false]
end
