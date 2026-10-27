defmodule LakehouseMatrix.SyncWait do
  @moduledoc "Wait for a committed stream change without rebuilding or locking a sync snapshot."
  alias LakehouseMatrix.ClientStore

  # The stream position advances in the same transaction as every delivered
  # change. A plain SELECT sees only committed positions and never holds up a
  # sender. Always rebuild at the deadline as well (expiry/authorization checks).
  def until_change(position, deadline, principal) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining > 0 do
      Process.sleep(min(remaining, 200))

      # Administrative account locks do not create Matrix events. Continue
      # checking them while idle so revocations still interrupt long polls.
      if ClientStore.position() == position and
           LakehouseMatrix.AccountModeration.check(principal, :read) == :ok,
         do: until_change(position, deadline, principal),
         else: :ok
    else
      :ok
    end
  end
end
