defmodule Macaw.Auth.Ash.MixProject do
  use Mix.Project

  @version "0.2.1"

  def project do
    [
      app: :macaw_auth_ash,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "A macaw_auth backend over AshAuthentication: a host's Ash user and token " <>
          "resources behind the Macaw.Auth contract, with an LDAP sign-in strategy.",
      package: [licenses: ["MIT"]],
      docs: [main: "readme", extras: ["README.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :eldap, :ssl, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:macaw_auth, git: "git@gitlab.conet.yarina.org:dco-tek/macaw_auth.git", tag: "v0.2.0"},
      {:ash, "~> 3.7"},
      {:ash_authentication, "~> 4.15"},
      {:ash_sqlite, "~> 0.3", only: :test},
      {:ecto_sqlite3, "~> 0.17", only: :test},
      # The test app's policies (Ash.Policy.Authorizer) need a SAT solver; this one is pure Elixir.
      {:simple_sat, "~> 0.1", only: :test},
      # Spec, tests and code kept aligned (macaw_compose spec/00 §4.1); dev/test only.
      {:surfex, "~> 0.10.0", only: [:dev, :test], runtime: false}
    ]
  end
end
