defmodule LakehouseMatrix.Social do
  @moduledoc "River's consent-scoped view of the shared Gravitas contacts graph."
  alias LakehouseIam.{Contacts, Identifier}
  alias LakehouseMatrix.Identity

  def list(g) do
    with {:ok, data} <- Contacts.list(g) do
      {friends, other_contacts} = Enum.split_with(data.contacts, & &1.uses_app)
      {:ok, %{friends: Enum.map(friends, &matrix_person/1),
        other_contacts: Enum.map(other_contacts, &matrix_person/1),
        requests: Enum.map(data.requests, &matrix_person/1), blocked: Enum.map(data.blocked, &matrix_person/1)}}
    end
  end
  def events(g), do: Contacts.events(g)
  def act(g, p) do
    with {:ok, username} <- Identity.parse_user_id(p["user_id"]) do
      Contacts.act(g, Map.put(p, "user_id", Identifier.format(username)))
    else
      _ -> {:error, :invalid_request}
    end
  end
  def friends?(a, b), do: Contacts.connected?(a, b)
  def blocked?(a, b), do: Contacts.blocked?(a, b)
  defp matrix_person(p), do: Map.put(p, :user_id, Identity.user_id(p.username))
end
