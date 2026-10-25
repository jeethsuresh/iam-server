defmodule LakehouseMatrix.MixProject do
  use Mix.Project

  def project do
    [
      app: :lakehouse_matrix,
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
      extra_applications: [:logger, :runtime_tools],
      mod: {LakehouseMatrix.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:lakehouse_iam, in_umbrella: true},
      {:req, "~> 0.5"},
      {:floki, "== 0.38.4"},
      {:plug_crypto, ">= 2.2.1 and < 3.0.0"},
      {:phoenix_pubsub, "~> 2.1"}
    ]
  end
end
