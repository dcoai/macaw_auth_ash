defmodule Macaw.Auth.Ash.Test.User do
  @moduledoc """
  The test app's user resource, as an Ash host declares one: a password
  strategy, the LDAP strategy (`nas`, used only when the backend's
  `strategies` name it), log-out-everywhere, a roles attribute, and the
  fields `Macaw.Auth.Ash` reads (display name, source, disabled).
  """

  use Ash.Resource,
    domain: Macaw.Auth.Ash.Test.Accounts,
    data_layer: AshSqlite.DataLayer,
    extensions: [AshAuthentication, Macaw.Auth.Ash.Strategy.Ldap],
    authorizers: [Ash.Policy.Authorizer]

  sqlite do
    table("users")
    repo(Macaw.Auth.Ash.Test.Repo)
  end

  authentication do
    tokens do
      enabled?(true)
      token_resource(Macaw.Auth.Ash.Test.Token)
      store_all_tokens?(true)
      require_token_presence_for_authentication?(true)
      token_lifetime({30, :days})
      signing_secret(fn _, _ -> {:ok, "macaw-auth-ash-test-signing-secret-of-some-length"} end)
    end

    strategies do
      password :password do
        identity_field(:username)
        hashed_password_field(:hashed_password)
      end

      ldap :nas do
        source({Macaw.Auth.Ash.Test.Directory, :nas, []})
        identity_field(:username)
        roles_field(:roles)
        source_field(:source)
        display_name_field(:display_name)
        disabled_field(:disabled_at)
      end
    end

    add_ons do
      log_out_everywhere do
        apply_on_password_change?(false)
      end
    end
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:username, :string, allow_nil?: false, public?: true)
    attribute(:hashed_password, :string, sensitive?: true, public?: false)
    attribute(:display_name, :string, public?: true)
    attribute(:roles, {:array, :string}, default: [], allow_nil?: false, public?: true)
    attribute(:source, :string, default: "local", allow_nil?: false, public?: true)
    attribute(:disabled_at, :utc_datetime_usec, public?: true)
  end

  # No actor may read or write a user: Macaw.Auth.Ash makes every call with
  # authorize?: false (spec 01), so the suite passing under this policy shows it.
  # AshAuthentication's own interactions keep their bypass, as its docs advise.
  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if(always())
    end

    policy always() do
      forbid_if(always())
    end
  end

  identities do
    identity(:unique_username, [:username])
  end

  actions do
    defaults([:read, :destroy])

    create :seed do
      accept([:username, :hashed_password, :display_name, :roles, :source])
    end

    update :disable do
      change(set_attribute(:disabled_at, &DateTime.utc_now/0))
    end
  end
end
