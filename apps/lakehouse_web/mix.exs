defmodule LakehouseWeb.MixProject do
  use Mix.Project

  def project do
    [
      app: :lakehouse_web,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_pattern: "*_test.exs",
      warn_test_pattern_mismatch: false
    ]
  end

  def application do
    [
      mod: {LakehouseWeb.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.7.14"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_view, "~> 1.0"},
      {:phoenix_ecto, "~> 4.5"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 0.26"},
      {:jason, "~> 1.2"},
      {:bandit, "~> 1.2"},
      {:req, "~> 0.5"},
      {:lakehouse_iam, in_umbrella: true},
      {:lakehouse_matrix, in_umbrella: true},
      {:cucumber, "~> 1.0", only: :test},
      {:wallaby, "~> 0.30", runtime: false, only: :test}
    ]
  end
end
