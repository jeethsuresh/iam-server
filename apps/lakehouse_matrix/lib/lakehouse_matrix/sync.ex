defmodule LakehouseMatrix.Sync do
  @moduledoc "Internal compatibility facade over commit-ordered Matrix sync."
  alias LakehouseMatrix.{ClientStore, ClientSync, Cursor}

  # Internal callers can capture a position without naming a user. HTTP cursors
  # are always signed and bound to the authenticated user and device.
  def current_token, do: "ms1.#{ClientStore.position()}"
  def parse_token(nil), do: 0

  def parse_token("ms1." <> rest) do
    case Integer.parse(rest) do
      {n, ""} when n >= 0 -> n
      _ -> 0
    end
  end

  def parse_token("mx1." <> _ = token) do
    with ["mx1", body, _] <- String.split(token, "."),
         {:ok, raw} <- Base.url_decode64(body, padding: false),
         {:ok, ["sync", _, "legacy", n, ""]} <- Jason.decode(raw),
         true <- is_integer(n) and n >= 0 do
      n
    else
      _ -> 0
    end
  end

  def parse_token(_), do: 0

  def sync(principal, since, opts \\ []) do
    token =
      cond do
        is_nil(since) -> nil
        String.starts_with?(since, "mx1.") -> since
        true -> Cursor.encode("sync", principal, "legacy", parse_token(since))
      end

    params = %{
      "since" => token,
      "full_state" => Keyword.get(opts, :full_state, is_nil(since)),
      "timeout" => Keyword.get(opts, :timeout, 0)
    }

    {:ok, response} = ClientSync.sync(principal, "legacy", params, update_presence: false)
    response
  end
end
