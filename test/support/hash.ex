defmodule Macaw.Auth.Ash.Test.Hash do
  @moduledoc """
  The test user's hash provider: AshAuthentication's bcrypt provider, telling
  the calling process each verification it does (macaw_auth_ash#1).

  "Spends a hash's time" is checked by what runs, never by timing two runs:
  elapsed time on a shared runner measures the runner. A verification against
  a hash (`valid?/2`) and one against nothing (`simulate/0`) are the same
  bcrypt work, so an attempt that does exactly one of them costs one hash,
  whichever it is. `hash/1` (registration) is not a verification.
  """

  @behaviour AshAuthentication.HashProvider

  alias AshAuthentication.BcryptProvider

  @impl true
  defdelegate hash(input), to: BcryptProvider

  @impl true
  def valid?(input, hash) do
    send(self(), {:hash_work, :valid?})
    BcryptProvider.valid?(input, hash)
  end

  @impl true
  def simulate do
    send(self(), {:hash_work, :simulate})
    BcryptProvider.simulate()
  end

  @doc "Runs `fun` and returns, in order, the verifications it did."
  @spec work((-> any())) :: [:valid? | :simulate]
  def work(fun) do
    drain()
    fun.()
    drain()
  end

  defp drain(acc \\ []) do
    receive do
      {:hash_work, op} -> drain([op | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
