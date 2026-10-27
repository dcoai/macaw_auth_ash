# The test app's database: a fresh SQLite file, migrated with the test
# app's migration (test/support), over a plain pool, then the repo
# restarted sandboxed: the sandbox has one connection (SQLite allows one
# writer), which the migrator would contend for.
alias Macaw.Auth.Ash.Test.Repo

tmp = Path.expand("../tmp/test", __DIR__)
File.rm_rf!(tmp)
File.mkdir_p!(tmp)

{:ok, migrating} = Repo.start_link(pool: DBConnection.ConnectionPool, pool_size: 1)
Ecto.Migrator.run(Repo, [{1, Macaw.Auth.Ash.Test.Migration}], :up, all: true, log: false)
:ok = Supervisor.stop(migrating)
{:ok, _} = Repo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)

# The :ldap tests need the OpenLDAP fixture directory (macaw's
# ci/tools/ldap image); they run when MACAW_AUTH_LDAP_HOST names it.
exclude = if System.get_env("MACAW_AUTH_LDAP_HOST"), do: [], else: [:ldap]

ExUnit.start(exclude: exclude)
