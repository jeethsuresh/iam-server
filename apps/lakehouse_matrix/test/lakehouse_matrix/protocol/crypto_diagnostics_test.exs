defmodule LakehouseMatrix.CryptoDiagnosticsTest do
  use ExUnit.Case, async: true

  test "wrong-typed crypto inputs cannot expose signing material in diagnostics" do
    secret = "synthetic-regression-key-never-use-in-production"

    operations = [
      fn -> Plug.Crypto.verify(secret, "matrix-test", ["invalid-token"]) end,
      fn -> Plug.Crypto.decrypt(secret, "matrix-test", %{"invalid" => true}) end,
      fn -> Plug.Crypto.secure_compare(nil, secret) end
    ]

    for operation <- operations do
      result =
        try do
          {:returned, operation.()}
        rescue
          error -> {:raised, Exception.format(:error, error, __STACKTRACE__)}
        end

      case result do
        {:returned, value} ->
          assert value in [false, :error, {:error, :invalid}, {:error, :missing}]

        {:raised, diagnostic} ->
          refute diagnostic =~ secret
      end
    end
  end
end
