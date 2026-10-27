defmodule Macaw.Auth.Ash.Test.Repo do
  @moduledoc "The test app's repo: SQLite through AshSqlite, standing in for a host's."
  use AshSqlite.Repo, otp_app: :macaw_auth_ash

  # The SQLite exqlite bundles is newer; this is what the tests need
  # (RETURNING, for bulk updates that return their records).
  def min_sqlite_version, do: %Version{major: 3, minor: 35, patch: 0}
end
