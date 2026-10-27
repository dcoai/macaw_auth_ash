import Config

# The library's own test setup only; a host configures its own. The test
# app (test/support) is an Ash domain on AshSqlite, its database a SQLite
# file under tmp/ (ignored), migrated by test_helper.
if config_env() == :test do
  config :macaw_auth_ash, Macaw.Auth.Ash.Test.Repo,
    database: Path.expand("../tmp/test/macaw_auth_ash_test.db", __DIR__),
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 1

  config :macaw_auth_ash,
    ecto_repos: [Macaw.Auth.Ash.Test.Repo],
    ash_domains: [Macaw.Auth.Ash.Test.Accounts]

  # Ash's current defaults, as `mix igniter.install ash` sets them.
  config :ash, default_string_length_count: :codepoints

  # Every Ash action in the test process, so the SQL sandbox sees it.
  config :ash, disable_async?: true

  config :macaw_auth, backend: Macaw.Auth.Ash

  config :macaw_auth, Macaw.Auth.Ash,
    user_resource: Macaw.Auth.Ash.Test.User,
    strategies: [:password],
    roles_from: :roles,
    username_field: :username,
    display_name_field: :display_name,
    source_field: :source,
    disabled_field: :disabled_at,
    idle_days: 14

  # Cheap hashes: the tests count work, not seconds.
  config :bcrypt_elixir, log_rounds: 4

  config :logger, level: :warning
end
