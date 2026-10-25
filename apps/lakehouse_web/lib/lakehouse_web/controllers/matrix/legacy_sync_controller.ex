defmodule LakehouseWeb.Matrix.LegacySyncController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.LegacySync
  alias LakehouseWeb.Matrix.ProtocolController

  def initial(conn, params),
    do:
      ProtocolController.respond(
        conn,
        LegacySync.initial(conn.assigns.principal_id, conn.assigns.matrix_device_id, params)
      )

  def room(conn, %{"roomId" => ref} = params),
    do:
      ProtocolController.respond(
        conn,
        LegacySync.room(conn.assigns.principal_id, conn.assigns.matrix_device_id, ref, params)
      )

  def event(conn, %{"eventId" => id}),
    do: ProtocolController.respond(conn, LegacySync.event(conn.assigns.principal_id, id))

  def stream(conn, params),
    do:
      ProtocolController.respond(
        conn,
        LegacySync.stream(conn.assigns.principal_id, conn.assigns.matrix_device_id, params)
      )
end
