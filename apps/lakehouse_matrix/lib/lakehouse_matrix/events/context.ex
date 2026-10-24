defmodule LakehouseMatrix.Events.Context do
  @moduledoc """
  Input to an event handler: room, sender, and raw Matrix event fields.
  """
  defstruct [
    :room_id,
    :principal_id,
    :sender,
    :event_id,
    :type,
    :content,
    :state_key,
    :origin_server_ts,
    :sticky_duration_ms
  ]

  @type t :: %__MODULE__{
          room_id: Ecto.UUID.t(),
          principal_id: Ecto.UUID.t(),
          sender: String.t(),
          event_id: String.t(),
          type: String.t(),
          content: map(),
          state_key: String.t() | nil,
          origin_server_ts: integer()
        }
end
