defmodule LakehouseMatrix.AccountModeration do
  @moduledoc "Reversible Matrix moderation, independent of IAM account approval and token revocation."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Schema.Principal
  alias LakehouseMatrix.{ClientStore, Identity}

  def status(id), do: Repo.get(Principal, id)

  def check(id, mode \\ :write) do
    case status(id) do
      %Principal{matrix_deactivated: true} when mode == :leave -> :ok
      %Principal{matrix_deactivated: true} when mode != :leave -> {:error, :user_deactivated}
      %Principal{matrix_locked: true} -> {:error, :user_locked}
      %Principal{matrix_suspended: true} when mode == :write -> {:error, :user_suspended}
      _ -> :ok
    end
  end

  def require!(id, mode \\ :write) do
    case check(id, mode) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  def admin(actor, user, field, value \\ :get)
      when field in [:matrix_locked, :matrix_suspended] do
    Repo.transaction(fn ->
      ClientStore.lock!()
      account = Repo.get(Principal, actor)
      # Authorize before even parsing or looking up the target.
      unless account && account.active && Accounts.admin?(account.username),
        do: Repo.rollback(:forbidden)

      require!(actor)
      target = target!(user)
      if value != :get and not is_boolean(value), do: Repo.rollback(:invalid_param)
      if value != :get and target.id == actor, do: Repo.rollback(:forbidden)

      target =
        if value == :get,
          do: target,
          else: target |> Ecto.Changeset.change([{field, value}]) |> Repo.update!()

      key = if field == :matrix_locked, do: "locked", else: "suspended"
      %{key => Map.fetch!(target, field)}
    end)
  end

  def whois(actor, user) do
    account = Repo.get(Principal, actor)

    if account &&
         (Identity.user_id(account.username) == user or Accounts.admin?(account.username)) do
      Repo.transaction(fn ->
        require!(actor, :read)
        target = target!(user)

        devices =
          Repo.all(
            from d in "matrix_devices",
              where: d.principal_id == type(^target.id, :binary_id),
              select: d.device_id
          )

        # IP addresses and user agents are not retained. Do not invent connection history.
        %{"user_id" => user, "devices" => Map.new(devices, &{&1, %{"sessions" => []}})}
      end)
    else
      {:error, :forbidden}
    end
  end

  defp target!(user) do
    with {:ok, name} <- Identity.parse_user_id(user),
         {:ok, target} <- Accounts.fetch_user(name) do
      target
    else
      _ -> Repo.rollback(:not_found)
    end
  end

  # Only locally originated operations call this. Receiving historical, signed
  # federation PDUs must not be affected by later account moderation.
  def event(sender, room, type, content, key) do
    account =
      with {:ok, name} <- Identity.parse_user_id(sender),
           {:ok, p} <- Accounts.fetch_user(name),
           do: p

    case account do
      %Principal{matrix_deactivated: true} ->
        if type == "m.room.member" and key == sender and content["membership"] == "leave",
          do: :ok,
          else: {:error, :user_deactivated}

      %Principal{matrix_locked: true} ->
        {:error, :user_locked}

      %Principal{matrix_suspended: true} ->
        cond do
          type == "m.room.member" and key == sender and content["membership"] == "leave" -> :ok
          type == "m.room.redaction" and own_event?(room, content["redacts"], sender) -> :ok
          true -> {:error, :user_suspended}
        end

      _ ->
        :ok
    end
  end

  defp own_event?(room, id, sender) when is_binary(id) do
    Repo.exists?(
      from e in LakehouseMatrix.Schema.RoomEvent,
        where: e.room_id == ^room and e.event_id == ^id and e.sender == ^sender
    ) or
      Repo.exists?(
        from p in LakehouseMatrix.Schema.Pdu,
          where:
            p.local_room_id == ^room and p.event_id == ^id and
              fragment("?->>'sender'", p.pdu) == ^sender
      )
  end

  defp own_event?(_, _, _), do: false
end
