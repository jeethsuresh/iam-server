defmodule LakehouseIam.Registration do
  @moduledoc "Validates the invitation key required by public account registration."

  @spec authorize(term()) :: :ok | {:error, String.t()}
  def authorize(provided) do
    expected = Application.get_env(:lakehouse_iam, :registration_key)

    if is_binary(expected) and expected != "" and is_binary(provided) and
         :crypto.hash_equals(:crypto.hash(:sha256, expected), :crypto.hash(:sha256, provided)) do
      :ok
    else
      {:error, "A valid registration key is required."}
    end
  end
end
