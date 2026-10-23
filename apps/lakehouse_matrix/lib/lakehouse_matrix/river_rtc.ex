defmodule LakehouseMatrix.RiverRtc do
  @moduledoc "MatrixRTC room slots and short-lived, authenticated device memberships. Media is relayed by the configured SFU."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseIam.Apps.Tokens
  alias LakehouseMatrix.{DelegatedGroups, Identity, Memberships, State}
  alias LakehouseMatrix.Schema.{RiverRtcMember, RoomEvent}
  @slot "m.call#room"
  def update(g, token, room, p) do
    if "calls.join" not in g.scopes, do: {:error, :insufficient_scope}, else: do_update(g, token, room, p)
  end
  defp do_update(g, token, room, p) do
    DelegatedGroups.with_room(g, room, "chats.write", fn ->
      unless allowed_target?(room), do: Repo.rollback(:forbidden)
      url = Application.get_env(:lakehouse_matrix, :rtc_url)
      unless is_binary(url) and String.starts_with?(url, "wss://"), do: Repo.rollback(:rtc_unavailable)
      id = p["member_id"]
      unless is_binary(id) and String.match?(id, ~r/^[a-zA-Z0-9_-]{43}$/) and p["action"] in ~w(join renew leave), do: Repo.rollback(:invalid_request)
      existing = Repo.get(RiverRtcMember, id)
      if existing && (existing.principal_id != g.principal_id or existing.room_id != room or existing.app_origin != g.app_origin or existing.token_id != token.id), do: Repo.rollback(:forbidden)
      now = DateTime.utc_now()
      if p["action"] == "join" and is_nil(existing) do
        count = Repo.aggregate(from(m in RiverRtcMember, where: m.principal_id == ^g.principal_id and m.expires_at > ^now), :count)
        if count >= 4, do: Repo.rollback(:too_many_connections)
        ensure_slot!(g, room)
        Repo.insert!(%RiverRtcMember{id: id, principal_id: g.principal_id, room_id: room, app_origin: g.app_origin, token_id: token.id, expires_at: DateTime.add(now,70,:second)})
      else
        unless existing && DateTime.compare(existing.expires_at, now) == :gt, do: Repo.rollback(:membership_expired)
        Ecto.Changeset.change(existing, expires_at: if(p["action"] == "leave", do: now, else: DateTime.add(now,70,:second))) |> Repo.update!()
      end
      record = Repo.get!(RiverRtcMember, id)
      membership = if p["action"] == "leave", do: "leave", else: "join"
      # A fresh event refreshes the sticky lease; the member identifier is stable
      # only within this single join lifecycle and cannot impersonate another user.
      content = %{"slot_id" => @slot, "member" => %{"id" => id, "membership" => membership}, "sticky_key" => id,
        "application" => %{"type" => "m.call", "m.call.intent" => "video"},
        "transports" => %{"published" => [%{"type" => "m.livekit", "url" => url}], "can_subscribe" => ["m.livekit"]}}
      event = DelegatedGroups.content_event!(g, room, "m.rtc.member", content, Ecto.UUID.generate())
      %{member_id: id, room_id: Identity.room_id(room), slot_id: @slot, sender: event["sender"],
        livekit_room: "river_" <> digest([Identity.room_id(room), @slot]), identity: digest([event["sender"], id]),
        expires_at: DateTime.to_unix(record.expires_at), transport_url: url, membership: membership}
    end)
  end
  def list(g) do
    with true <- "chats.read" in g.scopes and "calls.read" in g.scopes do
      rooms = DelegatedGroups.list(g) |> Enum.filter(&(&1.membership == "join")) |> Map.new(&{&1.id, &1})
      now = DateTime.utc_now()
      rows = Repo.all(from m in RiverRtcMember, where: m.room_id in ^Map.keys(rooms) and m.expires_at > ^now, limit: 512)
        |> Enum.filter(&active?/1)
      calls = for {id, members} <- Enum.group_by(rows, & &1.room_id) do
        %{group_id: id, name: rooms[id].name, slot_id: @slot,
          participants: Enum.map(members, fn m ->
            sender = LakehouseIam.Repo.get!(LakehouseIam.Schema.Principal, m.principal_id).username |> Identity.user_id()
            %{user_id: sender, member_id: m.id, identity: digest([sender, m.id])}
          end)}
      end
      {:ok, %{calls: calls}}
    else
      _ -> {:error, :insufficient_scope}
    end
  end
  # Pseudonymous random IDs reveal only whether a known lease is still active.
  # This allows the dedicated SFU reaper to enforce revocations after a Go restart
  # without storing users' access tokens or issuing a broad service credential.
  def lease_active?(id) when is_binary(id) and byte_size(id) == 43 do
    case Repo.get(RiverRtcMember, id) do
      nil -> false
      member -> active?(member)
    end
  end
  def lease_active?(_), do: false
  defp active?(m) do
    with true <- DateTime.compare(m.expires_at, DateTime.utc_now()) == :gt,
         {:ok, %{grant: grant, token: token}} <- Tokens.verify_access_id(m.token_id),
         g = %{grant | scopes: Tokens.effective_scopes(token, grant)},
         true <- g.principal_id == m.principal_id and g.app_origin == m.app_origin and "calls.join" in g.scopes do
      DelegatedGroups.authorized?(g, m.room_id, "chats.write")
    else
      _ -> false
    end
  end
  defp allowed_target?(id) do
    meta = get_in(State.get(id, "cool.gravitas.river.group.v1") || %{}, ["content"]) || %{}
    meta["kind"] in ["dm", "group"] or (meta["kind"] == "channel" and meta["channel_kind"] == "drop_in")
  end
  defp ensure_slot!(g, room) do
    if is_nil(State.get(room, "m.rtc.slot", @slot)) do
      # The predefined default slot is part of the room template, including rooms
      # created before RTC was enabled. Its event is attributed to the creator.
      creator = Memberships.list_members(room) |> Enum.find(fn p -> LakehouseMatrix.Matrix.creator?(room, p.principal_id) end)
      unless creator, do: Repo.rollback(:forbidden)
      DelegatedGroups.template_state!(%{g | principal_id: creator.principal_id}, room, "m.rtc.slot", %{"status" => "open", "application" => %{"type" => "m.call"}}, @slot)
    end
  end
  defp digest(value), do: :crypto.hash(:sha256, Jason.encode!(value)) |> Base.encode64(padding: false)
  def sticky(room) do
    now = System.system_time(:millisecond)
    Repo.all(from e in RoomEvent, where: e.room_id == ^room and e.type == "m.rtc.member" and e.origin_server_ts > ^(now - 70_000), order_by: [asc: e.origin_server_ts, asc: e.id])
      |> Enum.map(&LakehouseMatrix.Events.to_client_event/1)
  end
end
