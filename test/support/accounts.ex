defmodule Macaw.Auth.Ash.Test.Accounts do
  @moduledoc "The test app's accounts domain: a user resource and its token resource."
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(Macaw.Auth.Ash.Test.User)
    resource(Macaw.Auth.Ash.Test.Token)
  end
end
