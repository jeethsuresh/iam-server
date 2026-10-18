defmodule LakehouseWeb.Bdd.Hooks do
  use Cucumber.Hooks

  alias LakehouseWeb.MatrixFixtures

  before_scenario context do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(LakehouseIam.Repo)
    Ecto.Adapters.SQL.Sandbox.mode(LakehouseIam.Repo, {:shared, self()})
    MatrixFixtures.ensure_rbac!()

    context =
      if browser_scenario?(context) do
        metadata = Phoenix.Ecto.SQL.Sandbox.metadata_for(LakehouseIam.Repo, self())
        {:ok, session} = Wallaby.start_session(metadata: metadata)
        Map.put(context, :session, session)
      else
        Map.put(context, :conn, Phoenix.ConnTest.build_conn())
      end

    {:ok, context}
  end

  after_scenario context do
    for {key, value} <- Map.get(context, :identity_config_before, %{}) do
      Application.put_env(:lakehouse_iam, key, value)
    end

    case Map.get(context, :session) do
      nil -> :ok
      session -> Wallaby.end_session(session)
    end

    :ok
  end

  defp browser_scenario?(context) do
    tags =
      []
      |> Kernel.++(List.wrap(Map.get(context, :tags)))
      |> Kernel.++(List.wrap(Map.get(context, :feature_tags)))
      |> Kernel.++(List.wrap(Map.get(context, :scenario_tags)))
      |> Enum.map(&normalize_tag/1)

    Enum.any?(tags, &(&1 == "browser"))
  end

  defp normalize_tag(tag) when is_atom(tag),
    do: tag |> Atom.to_string() |> String.trim_leading("@")

  defp normalize_tag(tag) when is_binary(tag), do: String.trim_leading(tag, "@")
  defp normalize_tag(_), do: ""
end
