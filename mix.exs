defmodule Macaw.Auth.Ash.MixProject do
  use Mix.Project

  @source_url "https://github.com/dcoai/macaw_auth_ash"
  @version "0.3.3"

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
      source_url: @source_url,
      package: package(),
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"],
        source_ref: "v#{@version}",
        logo: "brand/logo/macaw_scarlet.svg",
        assets: %{"brand/logo" => "brand/logo"}
      ]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :eldap, :ssl, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Published on Hex from its public home, mirrored from GitLab (dco-tek/macaw/macaw#155).
  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "https://hexdocs.pm/macaw_auth_ash/changelog.html"
      },
      files: ~w(lib spec mix.exs README.md LICENSE CHANGELOG.md .formatter.exs)
    ]
  end

  defp deps do
    [
      {:macaw_auth, "~> 0.4.1"},
      {:ash, "~> 3.7"},
      {:ash_authentication, "~> 4.15"},
      {:ash_sqlite, "~> 0.3", only: :test},
      {:ecto_sqlite3, "~> 0.17", only: :test},
      # The test app's policies (Ash.Policy.Authorizer) need a SAT solver; this one is pure Elixir.
      {:simple_sat, "~> 0.1", only: :test},
      # Docs for Hex (macaw_compose#155); dev only.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      # Spec, tests and code kept aligned (macaw_compose spec/00 §4.1); dev/test only.
      {:surfex, "~> 0.10.0", only: [:dev, :test], runtime: false}
    ]
  end
end
