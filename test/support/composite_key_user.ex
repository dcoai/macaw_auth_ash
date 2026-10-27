defmodule Macaw.Auth.Ash.Test.CompositeKeyUser do
  @moduledoc """
  A user resource keyed by two attributes, which `Macaw.Auth.Ash.Config`
  refuses: sessions name their user by one primary-key value. Only its DSL
  is read: no rows (ETS), in a domain of its own.
  """

  use Ash.Resource,
    domain: Macaw.Auth.Ash.Test.Elsewhere,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication]

  authentication do
    tokens do
      enabled?(true)
      token_resource(Macaw.Auth.Ash.Test.Token)
      require_token_presence_for_authentication?(true)
      token_lifetime({30, :days})
      signing_secret(fn _, _ -> {:ok, "macaw-auth-ash-test-signing-secret-of-some-length"} end)
    end

    strategies do
      password :password do
        identity_field(:username)
        hashed_password_field(:hashed_password)
        registration_enabled?(false)
      end
    end
  end

  attributes do
    attribute(:tenant, :string, primary_key?: true, allow_nil?: false, public?: true)
    attribute(:username, :string, primary_key?: true, allow_nil?: false, public?: true)
    attribute(:hashed_password, :string, sensitive?: true)
  end

  identities do
    identity(:unique_username, [:username], pre_check_with: Macaw.Auth.Ash.Test.Elsewhere)
  end

  actions do
    defaults([:read])
  end
end
