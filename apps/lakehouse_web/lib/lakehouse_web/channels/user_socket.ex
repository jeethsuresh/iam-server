defmodule LakehouseWeb.UserSocket do
  use Phoenix.Socket

  channel "room:*", LakehouseWeb.RoomChannel

  @impl true
  def connect(params, socket, _connect_info) do
    token =
      cond do
        is_binary(params["token"]) -> params["token"]
        is_map(params) -> Map.get(params, :token) || Map.get(params, "token")
        true -> nil
      end

    if token do
      connect_with_token(token, socket)
    else
      :error
    end
  end

  defp connect_with_token(token, socket) do
    case LakehouseIam.Auth.Token.verify(token) do
      {:ok, claims} ->
        u = claims["username"]

        case LakehouseIam.Accounts.fetch_user(u) do
          {:ok, principal} ->
            {:ok,
             socket
             |> assign(:username, u)
             |> assign(:principal_id, principal.id)}

          :error ->
            :error
        end

      :error ->
        :error
    end
  end

  @impl true
  def id(socket), do: "user_socket:#{socket.assigns.principal_id}"
end
