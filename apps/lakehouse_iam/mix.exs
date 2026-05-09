defmodule LakehouseIam.MixProject do
  use Mix.Project

  def project do
    [
      app: :lakehouse_iam,
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
      mod: {LakehouseIam.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, ">= 0.0.0"},
      {:argon2_elixir, "~> 4.0"},
      {:jason, "~> 1.2"},
      {:jose, "~> 1.11"},
      {:req, "~> 0.5"}
    ]
  end
end
