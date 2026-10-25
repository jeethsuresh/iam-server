defmodule LakehouseMatrix.InvitePermission do
  @moduledoc "Account-controlled rejection of new room invitations and suppression of stored invites."
  alias LakehouseIam.Accounts
  alias LakehouseMatrix.{ClientStore, Identity}

  def blocked?(principal),
    do:
      (ClientStore.get_data(principal, "", "m.invite_permission_config") || %{})["default_action"] ==
        "block"

  # Historical PDUs still belong to the room graph. Apply this only to locally
  # originated invitations and the authenticated federation invitation API.
  def check("m.room.member", %{"membership" => "invite"}, user) do
    with {:ok, name} <- Identity.parse_user_id(user),
         {:ok, account} <- Accounts.fetch_user(name) do
      if blocked?(account.id), do: {:error, :invite_blocked}, else: :ok
    else
      _ -> :ok
    end
  end

  def check(_, _, _), do: :ok

  def filter(events, principal) do
    if blocked?(principal) do
      account = LakehouseIam.Repo.get!(LakehouseIam.Schema.Principal, principal)
      user = Identity.user_id(account.username)
      Enum.reject(events, &invite_for?(&1, user))
    else
      events
    end
  end

  def suppressed?(
        principal,
        %{"type" => "m.room.member", "content" => %{"membership" => "invite"}} = event
      ) do
    account = LakehouseIam.Repo.get!(LakehouseIam.Schema.Principal, principal)
    invite_for?(event, Identity.user_id(account.username)) and blocked?(principal)
  end

  def suppressed?(_, _), do: false

  defp invite_for?(event, user),
    do:
      event["type"] == "m.room.member" and event["state_key"] == user and
        get_in(event, ["content", "membership"]) == "invite"
end
