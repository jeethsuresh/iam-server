defmodule Lakehouse.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      releases: [
        lakehouse: [
          applications: [
            lakehouse_iam: :permanent,
            lakehouse_matrix: :permanent,
            lakehouse_web: :permanent
          ]
        ]
      ],
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  defp deps do
    []
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run apps/lakehouse_iam/priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["test"]
    ]
  end
end
