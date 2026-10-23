defmodule LakehouseWeb.DashboardHTML do
  use LakehouseWeb, :html
  embed_templates "dashboard_html/*"

  def initial(name), do: name |> String.first() |> String.upcase()
  def hostname(url), do: URI.parse(url).host

  def errors(form, field) do
    errors = if form.source.action, do: form.errors, else: []
    Keyword.get_values(errors, field) |> Enum.map_join(" · ", fn {message, _} -> message end)
  end
end
