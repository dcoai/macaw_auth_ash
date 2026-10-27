defmodule Macaw.Auth.Ash.Test.Elsewhere do
  @moduledoc """
  A domain for the resources tests define only to read their DSL (a host's
  token resource with its own actions, one missing the notifier): it
  accepts any resource, so none needs listing.
  """

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    allow_unregistered?(true)
  end
end
