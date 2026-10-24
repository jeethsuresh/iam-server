defmodule LakehouseWeb.Plugs.FederationAuth do
  @moduledoc "Matrix server signatures authorize federation routes independently of IAM sessions."
  import Plug.Conn
  def init(opts), do: opts

  def call(conn, _) do
    uri = conn.request_path <> if(conn.query_string == "", do: "", else: "?" <> conn.query_string)
    content = if conn.method in ~w(GET HEAD DELETE), do: nil, else: conn.body_params

    fetch =
      Application.get_env(
        :lakehouse_matrix,
        :federation_key_fetcher,
        &LakehouseMatrix.Federation.Transport.get_json/2
      )

    case LakehouseMatrix.Federation.Auth.verify(
           conn.method,
           uri,
           content,
           Enum.take(get_req_header(conn, "authorization"), 5),
           fetch
         ) do
      {:ok, origin} ->
        assign(conn, :matrix_origin, origin)

      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(
          401,
          Jason.encode!(%{
            "errcode" => "M_UNAUTHORIZED",
            "error" => "A valid X-Matrix signature is required"
          })
        )
        |> halt()
    end
  end
end
