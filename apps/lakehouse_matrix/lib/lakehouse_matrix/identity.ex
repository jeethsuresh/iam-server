defmodule LakehouseMatrix.Identity do
  @moduledoc """
  Matrix user and room identifiers for this homeserver.
  """

  @spec homeserver_domain() :: String.t()
  def homeserver_domain do
    Application.get_env(:lakehouse_matrix, :homeserver_domain, "localhost")
  end

  @spec parse_user_id(String.t()) :: {:ok, String.t()} | :error
  def parse_user_id("@" <> _ = input) do
    case LakehouseIam.Identifier.parse(input) do
      {:ok, %{username: username, domain: domain}} ->
        if domain == homeserver_domain(), do: {:ok, username}, else: :error

      _ ->
        :error
    end
  end

  def parse_user_id(_), do: :error

  @spec user_id(String.t()) :: String.t()
  def user_id(username) when is_binary(username) do
    "@#{username}:#{homeserver_domain()}"
  end

  @spec room_id(Ecto.UUID.t()) :: String.t()
  def room_id(room_uuid) when is_binary(room_uuid) do
    case LakehouseMatrix.Protocol.Graph.room(room_uuid) do
      nil -> "!#{room_uuid}:#{homeserver_domain()}"
      room -> room.room_id
    end
  end

  @spec room_alias(String.t()) :: String.t()
  def room_alias(alias_name) when is_binary(alias_name) do
    "##{alias_name}:#{homeserver_domain()}"
  end

  @spec parse_room_id(String.t()) :: {:ok, Ecto.UUID.t()} | :error
  def parse_room_id("!" <> rest) do
    case LakehouseMatrix.Protocol.Graph.room_by_id("!" <> rest) do
      %{local_room_id: id} ->
        {:ok, id}

      nil ->
        case String.split(rest, ":", parts: 2) do
          [uuid, domain] when byte_size(uuid) > 0 ->
            if domain == homeserver_domain(), do: Ecto.UUID.cast(uuid), else: :error

          _ ->
            :error
        end
    end
  end

  def parse_room_id(uuid) when is_binary(uuid) do
    if String.match?(uuid, ~r/^[0-9a-f-]{36}$/i) do
      Ecto.UUID.cast(uuid)
    else
      :error
    end
  end

  def parse_room_id(_), do: :error

  @spec parse_room_alias(String.t()) :: {:ok, String.t()} | :error
  def parse_room_alias("#" <> rest) do
    case String.split(rest, ":", parts: 2) do
      [alias_name, domain] when byte_size(alias_name) > 0 ->
        if domain == homeserver_domain(), do: {:ok, alias_name}, else: :error

      _ ->
        :error
    end
  end

  def parse_room_alias(_), do: :error

  @spec resource_arn(Ecto.UUID.t()) :: String.t()
  def resource_arn(room_uuid) do
    "arn:lakehouse:matrix:room:#{room_uuid}"
  end

  @spec new_event_id() :: String.t()
  def new_event_id do
    "$" <> Base.url_encode64(:crypto.strong_rand_bytes(18), padding: false)
  end
end
