defmodule LakehouseMatrix.Cursor do
  @moduledoc "Authenticated Matrix cursors; positions are private to a user, device and purpose."
  def encode(kind, principal, device, position, room \\ "") do
    body =
      Jason.encode!([kind, principal, device, position, room])
      |> Base.url_encode64(padding: false)

    "mx1." <> body <> "." <> signature(body)
  end

  def decode(token, kind, principal, device, room \\ "")
  def decode(nil, "topology", _, _, _), do: {:ok, nil}
  def decode(nil, _, _, _, _), do: {:ok, 0}

  def decode(token, kind, principal, device, room)
      when is_binary(token) and byte_size(token) <= 2048 do
    with ["mx1", body, sig] <- String.split(token, "."),
         true <- Plug.Crypto.secure_compare(signature(body), sig),
         {:ok, raw} <- Base.url_decode64(body, padding: false),
         {:ok, [^kind, ^principal, ^device, position, ^room]} <- Jason.decode(raw),
         true <- valid_position?(kind, position) do
      {:ok, position}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  def decode(_, _, _, _, _), do: {:error, :invalid_cursor}

  defp valid_position?(kind, [depth, id]) when kind in ["topology", "threads"],
    do:
      is_integer(depth) and depth in -1..9_007_199_254_740_992 and is_binary(id) and
        byte_size(id) <= 255

  defp valid_position?("notifications", [id, high]),
    do:
      is_integer(id) and id in 0..9_007_199_254_740_991 and is_integer(high) and high >= 0 and
        high <= LakehouseMatrix.ClientStore.position()

  defp valid_position?(kind, _) when kind in ["topology", "threads"], do: false

  defp valid_position?(kind, position),
    do:
      is_integer(position) and position >= 0 and
        position <= LakehouseMatrix.ClientStore.position() + if(kind == "history", do: 1, else: 0)

  defp signature(body) do
    secret = Application.fetch_env!(:lakehouse_iam, :jwt_secret)

    :crypto.mac(:hmac, :sha256, secret, "matrix-cursor:" <> body)
    |> Base.url_encode64(padding: false)
  end
end
