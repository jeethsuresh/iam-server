defmodule LakehouseWeb.Plugs.MatrixAccountPolicy do
  @moduledoc "Matrix account restrictions for authenticated protocol and delegated River requests."
  import Plug.Conn
  alias LakehouseMatrix.AccountModeration

  def init(opts), do: opts

  def call(conn, _opts) do
    # Router pipelines run before the controller sets :phoenix_action.
    action =
      case Phoenix.Router.route_info(
             conn.private[:phoenix_router] || LakehouseWeb.Router,
             conn.method,
             conn.request_path,
             conn.host
           ) do
        %{plug_opts: action} when is_atom(action) -> action
        _ -> nil
      end

    result =
      if conn.method == "POST" and action in [:logout, :logout_all] do
        :ok
      else
        AccountModeration.check(
          conn.assigns.principal_id,
          if(read_or_recovery?(conn, action), do: :read, else: :write)
        )
      end

    case result do
      :ok ->
        conn

      {:error, reason} ->
        conn |> LakehouseWeb.Matrix.ProtocolController.respond({:error, reason}) |> halt()
    end
  end

  defp read_or_recovery?(conn, action) do
    conn.method == "GET" or
      action in [
        :login,
        :refresh,
        :sync,
        :sliding_sync,
        :search,
        :user_directory,
        :public_rooms,
        :keys_query,
        :keys_claim,
        :keys_upload,
        :cross_signing_upload,
        :signatures_upload,
        :backup_version,
        :backup_keys,
        :delete_device,
        :delete_devices,
        :update_device,
        :login_token,
        :put_data,
        :tags,
        :create_filter,
        :receipt,
        :read_markers,
        :forget,
        :leave_room,
        :redact,
        :deactivate,
        :mark_read,
        :read
      ] or
      (action == :send_event and conn.path_params["eventType"] == "m.room.redaction") or
      (action == :send_to_device and recovery_event?(conn.path_params["eventType"])) or
      (action == :membership and conn.body_params["action"] == "leave")
  end

  defp recovery_event?(type) when is_binary(type),
    do:
      type in ~w(m.room.encrypted m.room_key m.room_key_request m.forwarded_room_key m.secret.request m.secret.send) or
        String.starts_with?(type, "m.key.verification.")

  defp recovery_event?(_), do: false
end
