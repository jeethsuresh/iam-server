defmodule LakehouseWeb.DashboardController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Apps.Catalog
  plug :put_layout, html: {LakehouseWeb.Layouts, :dashboard}
  plug LakehouseWeb.Plugs.RequireAdmin when action in [:catalog, :create, :delete]

  def index(conn, _params) do
    render(conn, :index,
      directory: Catalog.dashboard(conn.assigns.principal_id),
      active_page: :services
    )
  end

  def launch(conn, %{"id" => id}) do
    case Catalog.get(id) do
      nil -> conn |> put_status(:not_found) |> text("Service not found")
      service -> redirect(conn, external: Catalog.launch_url(service, conn.assigns.username))
    end
  end

  def catalog(conn, _params), do: render_catalog(conn, nil)

  def create(conn, %{"service" => attrs}) do
    case Catalog.create(attrs) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "Service added to the catalog.")
        |> redirect(to: ~p"/services/manage")

      {:error, changeset} ->
        conn |> put_status(:unprocessable_entity) |> render_catalog(changeset)
    end
  end

  def delete(conn, %{"id" => id}) do
    case Catalog.get(id) do
      nil ->
        conn |> put_status(:not_found) |> text("Service not found")

      service ->
        {:ok, _} = Catalog.delete(service)

        conn
        |> put_flash(
          :info,
          "Service removed. Existing account connections can be managed in Settings."
        )
        |> redirect(to: ~p"/services/manage")
    end
  end

  defp render_catalog(conn, changeset) do
    changeset =
      changeset || LakehouseIam.Schema.Service.changeset(%LakehouseIam.Schema.Service{}, %{})

    render(conn, :catalog,
      services: Catalog.list(),
      form: Phoenix.Component.to_form(changeset, as: :service),
      active_page: :catalog
    )
  end
end
