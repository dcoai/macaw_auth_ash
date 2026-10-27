defmodule Macaw.Auth.Ash.Test.Directory do
  @moduledoc """
  The LDAP strategy's configuration for the test app: the OpenLDAP fixture
  directory (macaw's ci/tools/ldap image), as on the owner's NAS: direct
  bind over StartTLS with the test CA, posixGroup groups. Read at each
  sign-in, from `MACAW_AUTH_LDAP_HOST` and `MACAW_AUTH_LDAP_PORT`, the way
  a host reads its directory's settings at runtime.
  """

  @base "dc=example,dc=test"

  @doc "The `nas` strategy's directory."
  def nas do
    %{
      host: System.get_env("MACAW_AUTH_LDAP_HOST", "localhost"),
      port: String.to_integer(System.get_env("MACAW_AUTH_LDAP_PORT", "389")),
      ssl: false,
      starttls: true,
      cacertfile: Path.expand("../fixtures/ldap/ca.pem", __DIR__),
      user_dn_template: "uid={username},cn=users,#{@base}",
      groups: %{base_dn: "cn=groups,#{@base}", member_attr: "memberUid"},
      required_group: "macaw",
      role_mapping: %{"macaw-admin" => "admin"},
      default_role: "viewer"
    }
  end
end
