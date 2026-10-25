defmodule LakehouseMatrix.Protocol.Event do
  @moduledoc "Room-version 11/12 PDU encoding, redaction, hashing and signature checks."
  alias LakehouseMatrix.Federation.{Signing, Transport}

  @versions ["11", "12"]
  @maximum_integer 9_007_199_254_740_991
  @retained ~w(event_id type room_id sender state_key content hashes signatures depth prev_events auth_events origin_server_ts)
  @power_keys ~w(ban events events_default invite kick redact state_default users users_default)

  def versions, do: @versions

  def user_domain("@" <> rest = user) when byte_size(user) <= 255 do
    case String.split(rest, ":", parts: 2) do
      [local, server] when local != "" ->
        if String.valid?(local) and not String.contains?(local, ["\x00", "\n", "\r"]) and
             match?({:ok, _}, Transport.server_name(server)),
           do: {:ok, server},
           else: :error

      _ ->
        :error
    end
  end

  def user_domain(_), do: :error

  def redact(event, version) when version in @versions do
    content = event["content"] || %{}

    kept =
      case event["type"] do
        "m.room.create" ->
          content

        "m.room.member" ->
          content = Map.take(content, ~w(membership join_authorised_via_users_server))

          case get_in(event, ["content", "third_party_invite", "signed"]) do
            signed when is_map(signed) ->
              Map.put(content, "third_party_invite", %{"signed" => signed})

            _ ->
              content
          end

        "m.room.join_rules" ->
          Map.take(content, ~w(join_rule allow))

        "m.room.power_levels" ->
          Map.take(content, @power_keys)

        "m.room.history_visibility" ->
          Map.take(content, ["history_visibility"])

        "m.room.redaction" ->
          Map.take(content, ["redacts"])

        _ ->
          %{}
      end

    event |> Map.take(@retained) |> Map.put("content", kept)
  end

  def content_hash(event) do
    event |> Map.drop([:auth_rejected | ~w(unsigned signatures hashes event_id)]) |> digest()
  end

  def reference_hash(event, version) do
    event
    |> Map.delete("event_id")
    |> redact(version)
    |> Map.drop(~w(signatures unsigned))
    |> digest()
  end

  def id(event, version),
    do: "$" <> Base.url_encode64(reference_hash(event, version), padding: false)

  def room_id(%{"type" => "m.room.create"} = event, "12"),
    do: "!" <> Base.url_encode64(reference_hash(event, "12"), padding: false)

  def room_id(event, _version), do: event["room_id"]

  def sign(event, version, seed, key_id, server) when version in @versions do
    event =
      event
      |> Map.delete("event_id")
      |> Map.put("hashes", %{"sha256" => Base.encode64(content_hash(event), padding: false)})

    add_signature(event, version, seed, key_id, server)
  end

  def add_signature(event, version, seed, key_id, server) do
    signed =
      event |> Map.delete("event_id") |> redact(version) |> Signing.sign(seed, key_id, server)

    Map.put(event, "signatures", signed["signatures"])
  end

  @doc "The key lookup must return a public key valid at the supplied event timestamp."
  def verify(event, version, lookup) when version in @versions do
    LakehouseMatrix.Federation.Keyring.with_cache(fn ->
      with :ok <- validate(event, version),
           :ok <- verify_required_signatures(event, version, lookup) do
        selected = if hash_matches?(event), do: event, else: redact(event, version)
        {:ok, Map.put(selected, "event_id", id(event, version))}
      end
    end)
  rescue
    _ -> {:error, :invalid_event}
  end

  def verify(_, _, _), do: {:error, :unsupported_room_version}

  def verify_sender(event, version, lookup) do
    LakehouseMatrix.Federation.Keyring.with_cache(fn ->
      with :ok <- validate(event, version),
           {:ok, server} <- user_domain(event["sender"]),
           true <- signed_by?(event, version, server, lookup),
           do: :ok,
           else: (_ -> {:error, :invalid_signature})
    end)
  end

  def validate(event, version) when is_map(event) and version in @versions do
    valid =
      is_map(event["content"]) and match?({:ok, _}, user_domain(event["sender"])) and
        bounded_string?(event["type"], 1, 255) and
        (not Map.has_key?(event, "state_key") or bounded_string?(event["state_key"], 0, 255)) and
        is_integer(event["origin_server_ts"]) and
        is_integer(event["depth"]) and event["depth"] >= 0 and event["depth"] <= @maximum_integer and
        references?(event["auth_events"], 10) and references?(event["prev_events"], 20) and
        is_map(event["hashes"]) and valid_hash?(event["hashes"]["sha256"]) and
        signatures?(event["signatures"]) and
        (not Map.has_key?(event, "unsigned") or is_map(event["unsigned"])) and
        valid_room?(event, version) and
        byte_size(Signing.canonical(Map.delete(event, "event_id"))) <= 65_536

    if valid, do: :ok, else: {:error, :invalid_event}
  rescue
    _ -> {:error, :invalid_event}
  end

  def validate(_, _), do: {:error, :invalid_event}

  defp valid_room?(%{"type" => "m.room.create"} = event, "12"),
    do: not Map.has_key?(event, "room_id") and event["state_key"] == ""

  defp valid_room?(event, "12"),
    do: is_binary(event["room_id"]) and Regex.match?(~r/\A![A-Za-z0-9_-]{43}\z/, event["room_id"])

  defp valid_room?(%{"room_id" => "!" <> rest = room}, "11") when byte_size(room) <= 255 do
    case String.split(rest, ":", parts: 2) do
      [local, server] when local != "" ->
        String.valid?(local) and not String.contains?(local, "\x00") and
          match?({:ok, _}, Transport.server_name(server))

      _ ->
        false
    end
  end

  defp valid_room?(_, _), do: false

  defp verify_required_signatures(event, version, lookup) do
    # Third-party invitations are authenticated against their signed token by
    # Authorization, because the identity server need not be the sender's server.
    third_party =
      event["type"] == "m.room.member" and
        get_in(event, ["content", "membership"]) == "invite" and
        is_map(get_in(event, ["content", "third_party_invite"]))

    {:ok, sender} = user_domain(event["sender"])
    servers = if third_party, do: [], else: [sender]
    via = get_in(event, ["content", "join_authorised_via_users_server"])

    servers =
      if event["type"] == "m.room.member" and not is_nil(via) do
        case user_domain(via) do
          {:ok, server} -> [server | servers]
          _ -> [:invalid | servers]
        end
      else
        servers
      end

    if Enum.all?(Enum.uniq(servers), &signed_by?(event, version, &1, lookup)),
      do: :ok,
      else: {:error, :invalid_signature}
  end

  defp signed_by?(event, version, server, lookup) when is_binary(server) do
    Enum.any?(event["signatures"][server] || %{}, fn {key, signature} ->
      if String.starts_with?(key, "ed25519:") and is_binary(signature) do
        case lookup.(server, key, event["origin_server_ts"]) do
          {:ok, public} ->
            Signing.verify(redact(Map.delete(event, "event_id"), version), public, key, server)

          _ ->
            false
        end
      else
        false
      end
    end)
  end

  defp signed_by?(_, _, _, _), do: false

  def content_intact?(event), do: hash_matches?(event)

  defp hash_matches?(event) do
    case Base.decode64(event["hashes"]["sha256"], padding: false) do
      {:ok, hash} -> Plug.Crypto.secure_compare(content_hash(event), hash)
      _ -> false
    end
  end

  defp digest(event), do: :crypto.hash(:sha256, Signing.canonical(event))

  defp bounded_string?(value, min, max),
    do:
      is_binary(value) and String.valid?(value) and byte_size(value) >= min and
        byte_size(value) <= max

  defp references?(values, limit),
    do: is_list(values) and length(values) <= limit and Enum.all?(values, &event_id?/1)

  defp event_id?("$" <> id), do: byte_size(id) > 0 and byte_size(id) < 255 and String.valid?(id)
  defp event_id?(_), do: false

  defp valid_hash?(value) when is_binary(value) do
    case Base.decode64(value, padding: false) do
      {:ok, raw} -> byte_size(raw) == 32
      _ -> false
    end
  end

  defp valid_hash?(_), do: false

  defp signatures?(value) when is_map(value) do
    Enum.all?(value, fn {server, signatures} ->
      is_binary(server) and is_map(signatures) and
        Enum.all?(signatures, fn {id, sig} -> is_binary(id) and is_binary(sig) end)
    end)
  end

  defp signatures?(_), do: false
end
