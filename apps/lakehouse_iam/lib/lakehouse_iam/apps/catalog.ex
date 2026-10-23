defmodule LakehouseIam.Apps.Catalog do
  @moduledoc "Administrator-maintained service directory. Consent remains per user and origin."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.Service
  alias LakehouseIam.Apps.Grants

  def list, do: Repo.all(from s in Service, order_by: [asc: s.name, asc: s.id])

  def get(id) do
    case Ecto.UUID.cast(id) do
      {:ok, id} -> Repo.get(Service, id)
      :error -> nil
    end
  end

  def create(attrs), do: %Service{} |> Service.changeset(attrs) |> Repo.insert()
  def delete(service), do: Repo.delete(service)

  def dashboard(principal_id) do
    grants = Grants.list_for_principal(principal_id)
    origins = MapSet.new(grants, & &1.app_origin)
    services = list()
    {connected, available} = Enum.split_with(services, &MapSet.member?(origins, &1.origin))
    known = MapSet.new(services, & &1.origin)
    uncatalogued = Enum.reject(grants, &MapSet.member?(known, &1.app_origin))
    %{connected: connected, available: available, uncatalogued: uncatalogued}
  end

  # Only the public identifier crosses domains here; credentials and tokens stay out of URLs.
  def launch_url(service, username) do
    uri = URI.parse(service.login_url)

    query =
      URI.decode_query(uri.query || "")
      |> Map.put("login_hint", LakehouseIam.Identifier.format(username))

    URI.to_string(%{uri | query: URI.encode_query(query)})
  end
end
