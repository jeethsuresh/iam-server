defmodule LakehouseWeb.TypingLabel do
  @moduledoc false

  @spec format([String.t()]) :: String.t() | nil
  def format([]), do: nil
  def format([name]), do: "#{name} is typing"
  def format([a, b]), do: "#{a} and #{b} are typing"
  def format(_names), do: "Several people are typing"

  @spec usernames_from_mxids([String.t()], String.t()) :: [String.t()]
  def usernames_from_mxids(user_ids, exclude_username)
      when is_list(user_ids) and is_binary(exclude_username) do
    exclude = String.downcase(exclude_username)

    user_ids
    |> Enum.map(&mxid_username/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.reject(&(String.downcase(&1) == exclude))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp mxid_username("@" <> rest) do
    rest |> String.split(":", parts: 2) |> List.first()
  end

  defp mxid_username(other) when is_binary(other), do: other
  defp mxid_username(_), do: nil
end
