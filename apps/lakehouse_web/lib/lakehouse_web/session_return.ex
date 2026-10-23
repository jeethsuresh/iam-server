defmodule LakehouseWeb.SessionReturn do
  @moduledoc "One-use local navigation after browser authentication; mutations are never replayed."
  import Plug.Conn

  @pages ~w(/dashboard /groups /rooms /settings /profile /profile/password /admin /services/manage /oauth/consent)

  def remember(conn) do
    target =
      conn.request_path <> if(conn.query_string == "", do: "", else: "?" <> conn.query_string)

    if conn.method == "GET" and safe?(target),
      do: put_session(conn, :return_to, target),
      else: delete_session(conn, :return_to)
  end

  def consume(conn) do
    target = get_session(conn, :return_to)
    {delete_session(conn, :return_to), if(safe?(target), do: target, else: "/dashboard")}
  end

  # Leave room for the CSRF and auth data inside the signed browser cookie.
  defp safe?(target) when is_binary(target) and byte_size(target) in 1..1024 do
    uri = URI.parse(target)
    path = uri.path || ""
    decoded = URI.decode(path)

    uri.scheme == nil and uri.host == nil and uri.userinfo == nil and uri.fragment == nil and
      not Regex.match?(~r/[\x00-\x1f\x7f\\]/, target <> decoded) and
      not Enum.any?(String.split(decoded, "/"), &(&1 in [".", ".."])) and
      (path in @pages or Regex.match?(~r{\A/(groups|rooms)/[^/]+\z}, decoded) or
         Regex.match?(~r"\A/services/[0-9a-fA-F-]{36}/launch\z", path) or
         Regex.match?(~r{\A/media/[^/]+/[^/]+\z}, decoded))
  rescue
    ArgumentError -> false
  end

  defp safe?(_), do: false
end
