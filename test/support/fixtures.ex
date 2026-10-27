defmodule Macaw.Auth.Ash.Test.Fixtures do
  @moduledoc """
  What the conformance kit needs of `Macaw.Auth.Ash`, over the test app:
  each test in its own sandboxed transaction, users made through the user
  resource's own create action with a bcrypt hash, as a host's
  registration would make them.

  `stored_session_values/0` is every value of every column of every token
  row, read with plain SQL rather than through the resource, so the kit's
  "no token stored as it is" sees what the database holds (the `jti`,
  subject, purpose and the `extra_data` JSON), not what the resource
  chooses to load.

  The second factor is unsupported under this backend (`Macaw.Auth.Ash`),
  and the kit runs with its block pending, so `user!/1` refuses a
  `:second_factor` other than `:none` rather than pretend, and
  `enroll_second_factor!/1` enrolls nothing: the behavior requires it,
  and its code is one the backend refuses, as it refuses every code.
  """

  @behaviour Macaw.Auth.Conformance.Fixtures

  alias Macaw.Auth.Ash.Test.{Repo, User}

  # The sign-in throttle's counts are global (an ETS table macaw_auth's
  # application owns), so each test starts with none.
  @impl true
  def reset! do
    :ok = Macaw.Auth.Native.Throttle.reset()
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
  end

  @impl true
  def user!(attrs) do
    case Map.get(attrs, :second_factor, :none) do
      :none -> :ok
      other -> raise ArgumentError, "second_factor #{inspect(other)} is unsupported here"
    end

    n = System.unique_integer([:positive])
    password = "correct horse #{n}"

    record =
      User
      |> Ash.Changeset.for_create(
        :seed,
        %{
          username: Map.get(attrs, :username, "user#{n}"),
          hashed_password: Bcrypt.hash_pwd_salt(password),
          display_name: Map.get(attrs, :display_name, "User #{n}"),
          roles: Map.get(attrs, :roles, ["viewer"])
        },
        authorize?: false
      )
      |> Ash.create!()

    {Macaw.Auth.Ash.to_user(record), %{username: record.username, password: password}}
  end

  @impl true
  def disable!(user) do
    User
    |> Ash.get!(user.id, authorize?: false)
    |> Ash.Changeset.for_update(:disable, %{}, authorize?: false)
    |> Ash.update!()

    :ok
  end

  @impl true
  def idle_seconds, do: Macaw.Auth.Ash.Config.get().idle_days * 86_400

  @impl true
  def stored_session_values do
    Repo.query!("SELECT * FROM tokens").rows
    |> List.flatten()
    |> Enum.filter(&is_binary/1)
  end

  @impl true
  def enroll_second_factor!(_user), do: fn -> "000000" end
end
