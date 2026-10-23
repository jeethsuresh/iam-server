defmodule LakehouseIam.Identifier do
  @moduledoc "Separates a user's local username from their identity domain."

  def domain, do: Application.get_env(:lakehouse_iam, :identity_domain, "localhost")

  def format(username, domain \\ domain()), do: "@#{username}:#{domain}"

  def parse(input) when is_binary(input) do
    case String.split(String.trim(input), ":", parts: 2) do
      ["@" <> username, domain] ->
        username = String.downcase(username)
        domain = String.downcase(domain)

        if valid_username?(username) and valid_domain?(domain) do
          {:ok, %{username: username, domain: domain, user_id: format(username, domain)}}
        else
          {:error, "use @username:domain with a valid username and domain"}
        end

      _ ->
        {:error, "use @username:domain"}
    end
  end

  def parse(_), do: {:error, "use @username:domain"}

  # Bare usernames remain valid for local forms and existing integrations.
  # A qualified name must belong to this identity domain, never just the same localpart.
  def local_username("@" <> _ = input) do
    with {:ok, identity} <- parse(input),
         true <- identity.domain == domain() do
      {:ok, identity.username}
    else
      false -> {:error, "identity belongs to another domain"}
      error -> error
    end
  end

  def local_username(input) when is_binary(input) do
    username = input |> String.trim() |> String.downcase()
    if valid_username?(username), do: {:ok, username}, else: {:error, "invalid username"}
  end

  def local_username(_), do: {:error, "invalid username"}

  def valid_username?(username), do: Regex.match?(~r/\A[a-z0-9]{1,20}\z/, username)

  def valid_domain?(domain) do
    # A port is useful for local development and is part of a Matrix server name.
    case URI.new("https://" <> domain) do
      {:ok, %URI{host: host, path: path, query: nil, fragment: nil, userinfo: nil}} ->
        is_binary(host) and path in [nil, ""] and byte_size(domain) <= 253 and
          Regex.match?(~r/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\z/, domain) and
          Enum.all?(String.split(host, "."), fn label ->
            byte_size(label) in 1..63 and not String.starts_with?(label, "-") and
              not String.ends_with?(label, "-")
          end)

      _ ->
        false
    end
  end
end
