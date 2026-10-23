defmodule LakehouseAppDemo.MixProject do
  use Mix.Project

  def project do
    [
      app: :lakehouse_app_demo,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {LakehouseAppDemo.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:lakehouse_iam, in_umbrella: true},
      {:phoenix, "~> 1.7.14"},
      {:phoenix_html, "~> 4.1"},
      {:jason, "~> 1.2"},
      {:bandit, "~> 1.2"},
      {:req, "~> 0.5"}
    ]
  end
end
