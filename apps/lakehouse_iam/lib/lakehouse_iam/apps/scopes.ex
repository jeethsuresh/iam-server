defmodule LakehouseIam.Apps.Scopes do
  @moduledoc "Known OAuth-like scopes for third-party apps."

  @known ~w(profile.name chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels friends.read friends.manage native.broker)

  def known, do: @known

  @spec parse(String.t() | [String.t()] | nil) :: {:ok, [String.t()]} | {:error, String.t()}
  def parse(nil), do: {:ok, []}
  def parse(list) when is_list(list), do: validate(list)

  def parse(str) when is_binary(str) do
    str
    |> String.split(~r/\s+/, trim: true)
    |> validate()
  end

  defp validate(scopes) do
    unknown = Enum.reject(scopes, &(&1 in @known))

    if unknown == [] do
      {:ok, Enum.uniq(scopes)}
    else
      {:error, "unknown scopes: #{Enum.join(unknown, ", ")}"}
    end
  end

  @doc "True if `have` includes every scope in `need`."
  def covers?(have, need) when is_list(have) and is_list(need) do
    MapSet.subset?(MapSet.new(need), MapSet.new(have))
  end
end
