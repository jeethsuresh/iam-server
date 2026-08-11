defmodule LakehouseWeb.TypingLabelTest do
  use ExUnit.Case, async: true

  alias LakehouseWeb.TypingLabel

  test "empty list yields nil" do
    assert TypingLabel.format([]) == nil
  end

  test "one name" do
    assert TypingLabel.format(["alice"]) == "alice is typing"
  end

  test "two names" do
    assert TypingLabel.format(["alice", "bob"]) == "alice and bob are typing"
  end

  test "three or more" do
    assert TypingLabel.format(["alice", "bob", "carol"]) == "Several people are typing"
  end

  test "idle timeout is two seconds" do
    assert LakehouseWeb.RoomLive.typing_idle_ms() == 2_000
  end

  test "usernames_from_mxids excludes self and sorts" do
    ids = ["@bob:localhost", "@alice:localhost", "@carol:localhost"]
    assert TypingLabel.usernames_from_mxids(ids, "alice") == ["bob", "carol"]
  end
end
