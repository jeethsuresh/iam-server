defmodule LakehouseMatrix.ClientSso do
  @moduledoc "Browser-bound requests for explicit full Matrix account consent. Independent from delegated application grants."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientLogin, ClientStore}

  def start(url) do
    if valid_redirect?(url) do
      id = ClientStore.random()

      Repo.insert_all("matrix_sso_requests", [
        %{id: id, redirect_url: url, expires_at: DateTime.add(ClientStore.now(), 600, :second)}
      ])

      {:ok, id}
    else
      {:error, :invalid_param}
    end
  end

  def fetch(id) when is_binary(id),
    do:
      Repo.one(
        from r in "matrix_sso_requests",
          where: r.id == ^id and r.expires_at > ^ClientStore.now(),
          select: r.redirect_url
      )

  def fetch(_), do: nil

  def approve(principal, id) when is_binary(id) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      url = fetch(id) || Repo.rollback(:not_found)

      case ClientLogin.generate(principal, false) do
        {:ok, %{"login_token" => token}} ->
          Repo.delete_all(from r in "matrix_sso_requests", where: r.id == ^id)
          uri = URI.parse(url)
          # Preserve duplicate state/query parameters, replacing only loginToken.
          query =
            URI.query_decoder(uri.query || "")
            |> Enum.reject(fn {key, _} -> key == "loginToken" end)

          URI.to_string(%{uri | query: URI.encode_query(query ++ [{"loginToken", token}])})

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  def approve(_, _), do: {:error, :not_found}

  defp valid_redirect?(url) when is_binary(url) and byte_size(url) in 1..2048 do
    uri = URI.parse(url)

    schemes =
      Application.get_env(
        :lakehouse_matrix,
        :sso_redirect_schemes,
        ~w(river element io.element.android io.element.ios)
      )

    no_controls = not Regex.match?(~r/[\x00-\x20\x7f\\]/, url)

    no_controls and is_nil(uri.userinfo) and
      ((uri.scheme == "https" and is_binary(uri.host) and uri.host != "") or
         (uri.scheme == "http" and uri.host in ["127.0.0.1", "localhost", "::1"]) or
         uri.scheme in schemes)
  rescue
    ArgumentError -> false
  end

  defp valid_redirect?(_), do: false
end
