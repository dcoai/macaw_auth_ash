defmodule Macaw.Auth.Ash.Test.OwnActionsToken do
  @moduledoc """
  A token resource that defines one of `Macaw.Auth.Ash.TokenResource`'s
  actions itself, as a host may: the extension leaves the host's
  `:macaw_auth_update` as it is and adds the other two. Only its actions
  are read, so it keeps no rows (ETS), in a domain of its own.
  """

  use Ash.Resource,
    domain: Macaw.Auth.Ash.Test.Elsewhere,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.TokenResource, Macaw.Auth.Ash.TokenResource],
    notifiers: [Macaw.Auth.Ash.Notifier]

  actions do
    update :macaw_auth_update do
      description("the host's own")
      accept([:extra_data])
    end
  end
end
