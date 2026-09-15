defmodule LakehouseIam.Apps.OriginTest do
  use ExUnit.Case, async: true

  alias LakehouseIam.Apps.Origin

  test "same origin ignores path" do
    assert Origin.same_origin?(
             "http://127.0.0.1:4100/login",
             "http://127.0.0.1:4100/oauth/callback"
           )
  end

  test "different ports are different origins" do
    refute Origin.same_origin?("http://127.0.0.1:4100/", "http://127.0.0.1:4000/")
  end

  test "from_url strips path" do
    assert {:ok, "http://app.example.com:4100"} =
             Origin.from_url("http://app.example.com:4100/oauth/callback?x=1")
  end
end
