defmodule LakehouseMatrix.Protocol.Policy do
  @moduledoc "Matrix policy-server signatures, with local transaction replay so peer requests never hold room locks."
  alias LakehouseIam.Repo
  alias LakehouseMatrix.Federation.{RoomAccess, Signing, Transport}
  alias LakehouseMatrix.Protocol.Event
  @cache {__MODULE__, :drafts}

  def transaction(callback), do: run(fn -> Repo.transaction(callback) end)

  def run(callback) do
    if Repo.in_transaction?() or not is_nil(Process.get(@cache)) do
      callback.()
    else
      Process.put(@cache, %{})

      try do
        attempt(callback, 256, System.monotonic_time(:millisecond) + 30_000)
      after
        Process.delete(@cache)
      end
    end
  end

  defp attempt(callback, left, deadline) when left > 0 do
    case callback.() do
      {:error, {:policy_signature_required, key, event, policy, version}} ->
        if System.monotonic_time(:millisecond) >= deadline do
          {:error, :policy_unavailable}
        else
          case request(event, policy, version) do
            {:ok, signed} ->
              Process.put(@cache, Map.put(Process.get(@cache), key, signed))
              attempt(callback, left - 1, deadline)

            error ->
              error
          end
        end

      result ->
        result
    end
  end

  defp attempt(_, _, _), do: {:error, :policy_unavailable}

  # Cache every draft in an atomic operation, including exempt events. This
  # preserves predecessor IDs when a later event needs a policy signature and
  # the whole local transaction has to be retried.
  def prepare!(metadata, event, state) do
    key =
      {metadata.local_room_id, metadata.current_state, metadata.extremities, event["sender"],
       event["type"], event["state_key"], event["content"]}

    cache = Process.get(@cache) || %{}
    draft = cache[key] || event
    if not is_nil(Process.get(@cache)), do: Process.put(@cache, Map.put(cache, key, draft))

    case active(state) do
      nil ->
        draft

      policy ->
        if exempt?(draft) or valid_signature?(draft, policy, metadata.version),
          do: draft,
          else: Repo.rollback({:policy_signature_required, key, draft, policy, metadata.version})
    end
  end

  def active(state) do
    content = get_in(state, [{"m.room.policy", ""}, "content"]) || %{}
    via = content["via"]

    if is_binary(via) and is_map(content["public_keys"]) and
         is_binary(content["public_keys"]["ed25519"]) and
         RoomAccess.joined?(state, via),
       do: %{via: via, key: content["public_keys"]["ed25519"]}
  end

  def recommended?(event, state, version) do
    case active(state) do
      nil -> true
      policy -> exempt?(event) or valid_signature?(event, policy, version)
    end
  end

  def recover(event, state, version) do
    case active(state) do
      nil ->
        event

      policy ->
        if exempt?(event) or valid_signature?(event, policy, version) or Repo.in_transaction?() do
          event
        else
          case request(event, policy, version) do
            {:ok, signed} -> signed
            _ -> event
          end
        end
    end
  end

  def request(event, policy, version, requester \\ &Transport.request/4) do
    if Repo.in_transaction?() do
      {:error, :policy_unavailable}
    else
      wire = Map.drop(event, ["event_id", :auth_rejected])

      with {:ok, response} <- requester.(:post, policy.via, "/_matrix/policy/v1/sign", wire),
           true <- is_map(response),
           signature when is_binary(signature) <-
             get_in(response, [policy.via, "ed25519:policy_server"]),
           signed <-
             Map.update(
               wire,
               "signatures",
               %{policy.via => %{"ed25519:policy_server" => signature}},
               fn signatures ->
                 Map.update(
                   signatures,
                   policy.via,
                   %{"ed25519:policy_server" => signature},
                   &Map.put(&1, "ed25519:policy_server", signature)
                 )
               end
             ),
           true <- valid_signature?(signed, policy, version) do
        {:ok,
         if(event["event_id"], do: Map.put(signed, "event_id", event["event_id"]), else: signed)}
      else
        {:error, {:http, status, body}} when status in 400..599 and is_map(body) ->
          if is_binary(body["errcode"]) and is_binary(body["error"]) and
               byte_size(Jason.encode!(body)) <= 65_536,
             do: {:error, {:policy_error, status, body}},
             else: {:error, :policy_unavailable}

        _ ->
          {:error, :policy_unavailable}
      end
    end
  rescue
    _ -> {:error, :policy_unavailable}
  end

  defp exempt?(event), do: event["type"] == "m.room.policy" and event["state_key"] == ""

  defp valid_signature?(event, policy, version) do
    with {:ok, <<public::binary-size(32)>>} <- Base.decode64(policy.key, padding: false),
         do:
           Signing.verify(
             Event.redact(Map.delete(event, "event_id"), version),
             public,
             "ed25519:policy_server",
             policy.via
           ),
         else: (_ -> false)
  end
end
