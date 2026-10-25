defmodule LakehouseMatrix.ClientUia do
  @moduledoc "Short-lived, single-use password reauthentication bound to the user, device, action and exact request."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Identity}

  def challenge(principal, device, action, params, invalid \\ false) do
    session = ClientStore.random()

    Repo.insert_all("matrix_uia_sessions", [
      %{
        id: session,
        principal_id: ClientStore.dump_id(principal),
        device_id: device,
        action: action,
        request_hash: digest(params),
        expires_at: DateTime.add(ClientStore.now(), 600, :second)
      }
    ])

    body = %{
      "session" => session,
      "flows" => [%{"stages" => ["m.login.password"]}],
      "params" => %{},
      "completed" => []
    }

    body =
      if invalid,
        do: Map.merge(body, %{"errcode" => "M_FORBIDDEN", "error" => "Reauthentication failed"}),
        else: body

    {:error, {:uia, body}}
  end

  def perform(principal, device, action, params, callback) do
    auth = params["auth"]
    user = Repo.get!(LakehouseIam.Schema.Principal, principal)

    if valid_credentials?(auth, user) do
      result =
        Repo.transaction(fn ->
          ClientStore.lock!()

          session =
            Repo.one(
              from s in "matrix_uia_sessions",
                where: s.id == ^auth["session"],
                lock: "FOR UPDATE",
                select: %{
                  principal: type(s.principal_id, :binary_id),
                  device: s.device_id,
                  action: s.action,
                  hash: s.request_hash,
                  expires: type(s.expires_at, :utc_datetime_usec)
                }
            )

          unless not is_nil(session) and session.principal == principal and
                   session.device == device and session.action == action and
                   session.hash == digest(params) and
                   DateTime.compare(session.expires, ClientStore.now()) == :gt,
                 do: Repo.rollback(:reauth_required)

          Repo.delete_all(from s in "matrix_uia_sessions", where: s.id == ^auth["session"])

          case callback.() do
            {:ok, body} -> body
            {:error, reason} -> Repo.rollback(reason)
          end
        end)

      if result == {:error, :reauth_required},
        do: challenge(principal, device, action, params, true),
        else: result
    else
      challenge(principal, device, action, params, not is_nil(auth))
    end
  end

  defp valid_credentials?(auth, user) when is_map(auth) do
    identifier = auth["identifier"] || %{}
    provided = if is_map(identifier), do: identifier["user"] || auth["user"]

    provided =
      case Identity.parse_user_id(provided) do
        {:ok, name} -> name
        _ -> provided
      end

    auth["type"] == "m.login.password" and is_binary(auth["session"]) and
      provided == user.username and
      is_binary(auth["password"]) and Accounts.password_valid?(user.username, auth["password"])
  end

  defp valid_credentials?(_, _), do: false

  defp digest(params),
    do:
      params
      |> Map.delete("auth")
      |> :erlang.term_to_binary([:deterministic])
      |> ClientStore.hash()
end
