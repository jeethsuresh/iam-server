defmodule LakehouseWeb.Bdd.CatalogSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest
  alias LakehouseWeb.Test.Api.{CatalogClient, IamClient}

  step "the administrator catalogs the service with sign-in URL {string}",
       %{args: [url]} = context do
    admin = context.admin
    %{"token" => token} = IamClient.login(admin.username, admin.password) |> json_response(200)
    {:ok, Map.put(context, :last_conn, CatalogClient.add(token, url))}
  end

  step "I catalog the service with sign-in URL {string}", %{args: [url]} = context do
    {:ok, Map.put(context, :last_conn, CatalogClient.add(context.token, url))}
  end

  step "the shared catalog should include {string}", %{args: [name]} = context do
    body = CatalogClient.list(context.token) |> json_response(200)
    assert Enum.any?(body["services"], &(&1["name"] == name))
    :ok
  end
end
