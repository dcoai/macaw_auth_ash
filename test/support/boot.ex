defmodule Macaw.Auth.Ash.Test.Boot do
  @moduledoc """
  Starts macaw_auth's application again under a changed backend
  configuration, as a host's boot would: what decides whether it starts is
  the backend's `check_config!/0`, which the application calls.

  Only for tests that aren't async: stopping `:macaw_auth` takes its
  Registry and the throttle's table down while it restarts.
  """

  @doc """
  Stops `:macaw_auth`, merges `changes` into `config :macaw_auth,
  Macaw.Auth.Ash`, starts it again, and gives that start's answer. Before
  answering, it puts the setting back and starts `:macaw_auth` as it was, so
  nothing after it sees the change; an `on_exit` does the same if the test
  fails first.
  """
  def boot_with(changes) do
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Ash)
    put_back = fn -> put_back(previous) end
    ExUnit.Callbacks.on_exit(put_back)

    :ok = Application.stop(:macaw_auth)
    Application.put_env(:macaw_auth, Macaw.Auth.Ash, Keyword.merge(previous, changes))
    result = Application.ensure_all_started(:macaw_auth)
    put_back.()
    result
  end

  defp put_back(previous) do
    if List.keymember?(Application.started_applications(), :macaw_auth, 0),
      do: :ok = Application.stop(:macaw_auth)

    Application.put_env(:macaw_auth, Macaw.Auth.Ash, previous)
    {:ok, _} = Application.ensure_all_started(:macaw_auth)
  end
end
