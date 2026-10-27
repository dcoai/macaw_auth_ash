defmodule Macaw.Auth.Ash.Test.Token do
  @moduledoc """
  The test app's token resource, as a host declares one for
  `Macaw.Auth.Ash`: AshAuthentication's token extension, Macaw's, and
  Macaw's notifier.
  """

  use Ash.Resource,
    domain: Macaw.Auth.Ash.Test.Accounts,
    data_layer: AshSqlite.DataLayer,
    extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
    notifiers: [Macaw.Auth.Ash.Notifier]

  sqlite do
    table("tokens")
    repo(Macaw.Auth.Ash.Test.Repo)
  end
end
