defmodule LakehouseMatrix.RiverReactions do
  @moduledoc "Validated emoji and portable sticker annotation keys."
  @emojis ~w(👍 👎 ❤️ 😂 🎉 🔥 👀 🙌 ✅ 🤔 😮 😢 🚀 💯 👏 ✨ 🫶 🙏 🥰 😎 🤯 💡 🌈 ☕)

  def valid?(key) when key in @emojis, do: true

  def valid?("sticker:" <> url) when byte_size(url) in 1..2048 do
    uri = URI.parse(url)

    uri.scheme in ["http", "https"] and is_binary(uri.host) and uri.host != "" and
      is_nil(uri.userinfo) and not String.contains?(url, "\\") and
      not Regex.match?(~r/[\s\x00-\x1f\x7f]/u, url)
  end

  def valid?(_), do: false
end
