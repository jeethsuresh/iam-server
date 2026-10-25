defmodule LakehouseMatrix.OpenId do
  @moduledoc "Short-lived identity attestations with credentials separate from Matrix access tokens."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}

  def issue(principal) do
    token = "oid_" <> ClientStore.random()

    Repo.transaction(fn ->
      ClientStore.lock!()
      LakehouseMatrix.AccountModeration.require!(principal, :read)
      Repo.delete_all(from t in "matrix_openid_tokens", where: t.expires_at <= ^ClientStore.now())

      Repo.insert_all("matrix_openid_tokens", [
        %{
          token_hash: ClientStore.hash(token),
          principal_id: ClientStore.dump_id(principal),
          expires_at: DateTime.add(ClientStore.now(), 3600, :second)
        }
      ])

      %{
        "access_token" => token,
        "token_type" => "Bearer",
        "matrix_server_name" => Identity.homeserver_domain(),
        "expires_in" => 3600
      }
    end)
  end

  def userinfo("oid_" <> _ = token) when byte_size(token) <= 255 do
    digest = ClientStore.hash(token)

    case Repo.one(
           from t in "matrix_openid_tokens",
             join: p in LakehouseIam.Schema.Principal,
             on: t.principal_id == p.id,
             where:
               t.token_hash == ^digest and t.expires_at > ^ClientStore.now() and p.active == true,
             select: p.username
         ) do
      nil -> {:error, :invalid_openid_token}
      name -> {:ok, %{"sub" => Identity.user_id(name)}}
    end
  end

  def userinfo(_), do: {:error, :invalid_openid_token}
end
