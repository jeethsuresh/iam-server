defmodule LakehouseWeb.Plugs.MatrixParsers do
  @moduledoc "Matrix JSON-object requests without mandatory Content-Type, with raw media bytes and Matrix parse errors."
  import Plug.Conn

  def init(opts) do
    {Plug.Parsers.init(opts),
     Plug.Parsers.init(Keyword.put(opts, :body_reader, {__MODULE__, :read_body, []}))}
  end

  def call(conn, {ordinary, matrix}) do
    if matrix_api?(conn.request_path) do
      conn = conn |> fetch_query_params() |> put_private(:phoenix_format, "json")

      cond do
        upload?(conn) ->
          token = LakehouseWeb.Plugs.MatrixAuth.token(conn)

          if is_binary(token) and not String.starts_with?(token, "mtx_"),
            do: Plug.Parsers.call(conn, ordinary),
            else: conn

        conn.method in ["POST", "PUT", "DELETE"] ->
          parse_json(conn, matrix)

        true ->
          conn
      end
    else
      Plug.Parsers.call(conn, ordinary)
    end
  end

  defp parse_json(conn, options) do
    conn =
      conn |> put_req_header("content-type", "application/json") |> Plug.Parsers.call(options)

    case conn.private[:matrix_json_root] do
      :empty ->
        if conn.method == "DELETE" or
             conn.request_path in ["/_matrix/client/v3/logout", "/_matrix/client/v3/logout/all"],
           do: conn,
           else: error(conn, 400, "M_NOT_JSON", "A JSON object is required")

      false ->
        error(conn, 400, "M_BAD_JSON", "The request body must be a JSON object")

      _ ->
        conn
    end
  rescue
    _ in Plug.Parsers.ParseError ->
      error(conn, 400, "M_NOT_JSON", "The request body is not valid JSON")

    _ in Plug.Parsers.RequestTooLargeError ->
      error(conn, 413, "M_TOO_LARGE", "The request body exceeds the server limit")

    _ in Plug.Parsers.UnsupportedMediaTypeError ->
      error(conn, 400, "M_NOT_JSON", "A JSON object is required")
  end

  def read_body(conn, opts) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, bytes, next} ->
        {:ok, bytes, put_private(next, :matrix_json_root, root(bytes))}

      result ->
        result
    end
  end

  defp root(<<c, rest::binary>>) when c in [32, 9, 10, 13], do: root(rest)
  defp root(""), do: :empty
  defp root("{" <> _), do: true
  defp root(_), do: false

  defp upload?(conn),
    do:
      conn.method in ["POST", "PUT"] and
        (conn.request_path == "/_matrix/media/v3/upload" or
           String.starts_with?(conn.request_path, "/_matrix/media/v3/upload/"))

  defp matrix_api?("/_matrix/client/v3/login/sso/redirect" <> _), do: false

  defp matrix_api?("/_matrix/client/v3/auth/" <> rest),
    do: not String.ends_with?(rest, "/fallback/web")

  defp matrix_api?("/_matrix/" <> _), do: true
  defp matrix_api?(_), do: false

  defp error(conn, status, code, message),
    do:
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, Jason.encode!(%{"errcode" => code, "error" => message}))
      |> halt()
end
