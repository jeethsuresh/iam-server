defmodule LakehouseWeb.NewtonD do
  @moduledoc false
  use GenServer
  alias Plug.Conn

  @port 5514
  @routes ["/app/v1/rtc", "/oauth/session", "/.well-known/iam-configuration"]

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @impl true
  def init(_) do
    host = System.get_env("NEWTOND_UDP_HOST")
    key = System.get_env("NEWTOND_UDP_KEY")

    if is_binary(host) and host != "" and is_binary(key) and byte_size(key) >= 32 do
      case :gen_udp.open(0, [:binary, active: false]) do
        {:ok, socket} -> {:ok, {socket, String.to_charlist(host), key}}
        {:error, _} -> :ignore
      end
    else
      :ignore
    end
  end

  def request_finished(%Conn{request_path: path, status: status} = conn, duration)
      when path in @routes and is_integer(status) do
    with pid when is_pid(pid) <- Process.whereis(__MODULE__),
         {:message_queue_len, size} when size < 256 <- Process.info(pid, :message_queue_len) do
      request_id =
        case Conn.get_req_header(conn, "x-newtond-request-id") do
          [id] when byte_size(id) in 26..64 ->
            if Regex.match?(~r/\A[A-Z2-7]+\z/, id), do: id, else: Ecto.UUID.generate()

          _ ->
            Ecto.UUID.generate()
        end

      send(pid, {
        :event,
        path,
        status,
        System.convert_time_unit(duration, :native, :nanosecond),
        request_id
      })
    end

    :ok
  end

  def request_finished(_, _), do: :ok

  @impl true
  def handle_info({:event, route, status, duration, request_id}, {socket, host, key} = state) do
    body =
      Jason.encode!(%{
        version: 1,
        id: Ecto.UUID.generate(),
        service: "iam",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        level: "info",
        message: "Gravitas request finished",
        params: %{
          route: %{type: "string", value: route},
          status: %{type: "int", value: Integer.to_string(status)},
          duration: %{type: "duration_ns", value: Integer.to_string(duration)},
          request_id: %{type: "string", value: request_id}
        }
      })

    mac = :crypto.mac(:hmac, :sha256, key, body) |> Base.encode16(case: :lower)
    :gen_udp.send(socket, host, @port, [mac, "\n", body])
    {:noreply, state}
  end
end
