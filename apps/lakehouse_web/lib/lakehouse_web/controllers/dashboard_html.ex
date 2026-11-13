defmodule LakehouseWeb.DashboardHTML do
  use LakehouseWeb, :html
  embed_templates "dashboard_html/*"

  def display_url(url), do: url |> String.replace_prefix("https://", "") |> String.trim_trailing("/")

  def branding_form(service, service_id, changeset) do
    selected = if service.id == service_id, do: changeset, else: Ecto.Changeset.change(service)
    Phoenix.Component.to_form(selected, as: :service)
  end
  def hostname(url), do: URI.parse(url).host

  def errors(form, field) do
    errors = if form.source.action, do: form.errors, else: []
    Keyword.get_values(errors, field) |> Enum.map_join(" · ", fn {message, _} -> message end)
  end
end
