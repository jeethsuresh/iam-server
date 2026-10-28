defmodule LakehouseWeb.PerformanceTest do
  use ExUnit.Case, async: true
  import Plug.Conn

  test "request timings distinguish SQL execution and pool waits without leaking SQL" do
    LakehouseWeb.Performance.attach()

    conn =
      Plug.Test.conn(:get, "/fixture/private-id")
      |> LakehouseWeb.Performance.call([])
      |> put_private(:phoenix_route, "/fixture/:id")

    :telemetry.execute(
      [:lakehouse_iam, :repo, :query],
      %{
        query_time: System.convert_time_unit(3, :millisecond, :native),
        queue_time: System.convert_time_unit(2, :millisecond, :native)
      },
      %{query: "sensitive SQL is deliberately ignored", params: ["private"]}
    )

    conn = send_resp(conn, 200, "ok")
    [timing] = get_resp_header(conn, "server-timing")
    assert timing =~ "db;dur=3.0"
    assert timing =~ "db_queue;dur=2.0"
    assert timing =~ "db_queries;desc=\"1\""
    refute timing =~ "private"
    refute timing =~ "SQL"
  end
end
