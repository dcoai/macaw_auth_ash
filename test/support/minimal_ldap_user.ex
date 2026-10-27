defmodule Macaw.Auth.Ash.Test.MinimalLdapUser do
  @moduledoc """
  A user resource whose LDAP strategy sets only its source, so its other
  options read as their defaults. Only its DSL is read: no rows (ETS), in
  a domain of its own.
  """

  use Ash.Resource,
    domain: Macaw.Auth.Ash.Test.Elsewhere,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap]

  authentication do
    strategies do
      ldap do
        source({Macaw.Auth.Ash.Test.Directory, :nas, []})
      end
    end
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:username, :string, allow_nil?: false, public?: true)
    attribute(:roles, {:array, :string}, default: [], public?: true)
    attribute(:source, :string, public?: true)
  end

  identities do
    identity(:unique_username, [:username], pre_check_with: Macaw.Auth.Ash.Test.Elsewhere)
  end

  actions do
    defaults([:read])
  end
end
