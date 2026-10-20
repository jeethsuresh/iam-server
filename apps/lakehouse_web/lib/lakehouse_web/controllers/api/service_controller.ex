defmodule LakehouseWeb.Api.ServiceController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Apps.Catalog
  plug LakehouseWeb.Plugs.RequireAdmin when action in [:create, :delete]

  def index(conn, _params), do: json(conn, %{services: Enum.map(Catalog.list(), &serialize/1)})

  def create(conn, %{"service" => attrs}) do
    case Catalog.create(attrs) do
      {:ok, service} ->
        conn |> put_status(:created) |> json(%{service: serialize(service)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: Ecto.Changeset.traverse_errors(changeset, fn {msg, _} -> msg end)})
    end
  end

  def delete(conn, %{"id" => id}) do
    case Catalog.get(id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      service ->
        {:ok, _} = Catalog.delete(service)
        send_resp(conn, :no_content, "")
    end
  end

  defp serialize(service),
    do: Map.take(service, [:id, :name, :description, :home_url, :login_url, :origin])
end
