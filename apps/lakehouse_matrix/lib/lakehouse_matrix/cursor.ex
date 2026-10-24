defmodule LakehouseMatrix.Cursor do
  @moduledoc "Authenticated Matrix cursors; positions are private to a user, device and purpose."
  def encode(kind, principal, device, position, room \\ "") do
    body =
      Jason.encode!([kind, principal, device, position, room])
      |> Base.url_encode64(padding: false)

    "mx1." <> body <> "." <> signature(body)
  end

  def decode(token, kind, principal, device, room \\ "")
  def decode(nil, _, _, _, _), do: {:ok, 0}

  def decode(token, kind, principal, device, room)
      when is_binary(token) and byte_size(token) <= 2048 do
    with ["mx1", body, sig] <- String.split(token, "."),
         true <- Plug.Crypto.secure_compare(signature(body), sig),
         {:ok, raw} <- Base.url_decode64(body, padding: false),
         {:ok, [^kind, ^principal, ^device, position, ^room]} <- Jason.decode(raw),
         true <-
           is_integer(position) and position >= 0 and
             position <=
               LakehouseMatrix.ClientStore.position() + if(kind == "history", do: 1, else: 0) do
      {:ok, position}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  def decode(_, _, _, _, _), do: {:error, :invalid_cursor}

  defp signature(body) do
    secret = Application.fetch_env!(:lakehouse_iam, :jwt_secret)

    :crypto.mac(:hmac, :sha256, secret, "matrix-cursor:" <> body)
    |> Base.url_encode64(padding: false)
  end
end
