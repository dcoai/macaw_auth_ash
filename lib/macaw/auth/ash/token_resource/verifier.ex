defmodule Macaw.Auth.Ash.TokenResource.Verifier do
  @moduledoc false
  use Spark.Dsl.Verifier

  alias Spark.Dsl.Verifier
  alias Spark.Error.DslError

  @impl true
  def verify(dsl) do
    if Macaw.Auth.Ash.Notifier in Ash.Resource.Info.notifiers(dsl) do
      :ok
    else
      {:error,
       DslError.exception(
         module: Verifier.get_persisted(dsl, :module),
         path: [:notifiers],
         message: """
         a token resource with Macaw.Auth.Ash.TokenResource needs its notifier, so a
         revocation made through Ash reaches open pages at once:

             use Ash.Resource, ..., notifiers: [Macaw.Auth.Ash.Notifier]
         """
       )}
    end
  end
end
