defmodule LakehouseWeb.ProtocolInteropTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Accounts, Protocols, Repo}
  alias LakehouseIam.Apps.Grants
  @moduletag skip: is_nil(System.get_env("PROTOCOL_INTEROP_APPSTORE_BINARY"))
  @store "https://apps.gravitas.cool"
  @sender "https://spacetime.gravitas.cool"
  @appstore Path.expand("../../../lakehouse_iam/test/fixtures/appstore-1.0.0.json", __DIR__)
            |> File.read!()
            |> Jason.decode!()

  test "real Spacetime event/outbox -> Gravitas registry/relay -> Private Store stream/ack" do
    prior =
      for k <- [:protocol_services, :protocol_owners, :public_url],
          into: %{},
          do: {k, Application.get_env(:lakehouse_iam, k)}

    on_exit(fn ->
      Enum.each(prior, fn {k, v} -> Application.put_env(:lakehouse_iam, k, v) end)
    end)

    Application.put_env(:lakehouse_iam, :protocol_services, %{
      @store => %{"key" => String.duplicate("r", 48), "permissions" => []},
      @sender => %{
        "key" => String.duplicate("n", 48),
        "permissions" => ["appstore.push", "protocols.read"]
      }
    })

    Application.put_env(:lakehouse_iam, :protocol_owners, %{"appstore" => @store})
    Application.put_env(:lakehouse_iam, :public_url, "https://gravitas.cool")
    {:ok, user} = Accounts.register_user("protocolinterop", "password123", approve: true)
    {:ok, grant} = Grants.upsert(user.id, @store, ["profile.name"], :all, [])

    assert {:ok, _} =
             Protocols.register(grant, %{"schema_version" => 1, "protocols" => [@appstore]})

    ready = Path.join(System.tmp_dir!(), "protocol-interop-#{Ecto.UUID.generate()}.json")
    on_exit(fn -> File.rm(ready) end)
    binary = System.fetch_env!("PROTOCOL_INTEROP_APPSTORE_BINARY")

    port =
      Port.open({:spawn_executable, binary}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["-test.run=^TestSpacetimeNotificationEndToEnd$", "-test.v", "-test.timeout=55s"],
        env:
          Enum.map(
            %{
              "PROTOCOL_INTEROP_READY" => ready,
              "PROTOCOL_INTEROP_IAM" => "http://127.0.0.1:#{System.get_env("PORT") || "4002"}",
              "NOTIFICATION_INTEROP_SUBJECT" => user.id,
              "SPACETIME_TEST_BINARY" => System.fetch_env!("PROTOCOL_INTEROP_SPACETIME_BINARY")
            },
            fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end
          )
      ])

    request = fn _, {key, envelope} ->
      %{"url" => url} = ready |> File.read!() |> Jason.decode!()

      case Req.post(url <> "/api/protocols/invoke",
             json: envelope,
             headers: [{"authorization", "Bearer " <> key}],
             retry: false
           ) do
        {:ok, %{status: 204}} -> :ok
        response -> flunk("Private Store rejected protocol delivery: #{inspect(response)}")
      end
    end

    {status, log} = pump(port, request, System.monotonic_time(:millisecond) + 60_000, "")
    assert status == 0, log
    assert Repo.aggregate(LakehouseIam.Protocols.Invocation, :count) >= 2
    assert Repo.aggregate(LakehouseIam.Protocols.Delivery, :count) == 0
  end

  defp pump(port, request, deadline, log) do
    if System.monotonic_time(:millisecond) > deadline do
      Port.close(port)
      flunk("Protocol integration timed out: #{log}")
    end

    Protocols.deliver_once(request)

    receive do
      {^port, {:data, chunk}} -> pump(port, request, deadline, log <> chunk)
      {^port, {:exit_status, status}} -> {status, log}
    after
      30 -> pump(port, request, deadline, log)
    end
  end
end
