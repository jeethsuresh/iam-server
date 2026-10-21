defmodule LakehouseWeb.Bdd.DiscoverySteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest
  @endpoint LakehouseWeb.Endpoint

  step "the identity domain {string} uses IAM at {string}", %{args: [domain, url]} = context do
    old = Map.new([:identity_domain, :public_url], &{&1, Application.get_env(:lakehouse_iam, &1)})

    ExUnit.Callbacks.on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_iam, key),
          else: Application.put_env(:lakehouse_iam, key, value)
      end
    end)

    Application.put_env(:lakehouse_iam, :identity_domain, domain)
    Application.put_env(:lakehouse_iam, :public_url, url)
    {:ok, context}
  end

  step "I discover the identity {string}", %{args: [input]} = context do
    {:ok, identity} = LakehouseIam.Identifier.parse(input)

    conn =
      get(build_conn(), "/.well-known/webfinger",
        resource: LakehouseIam.Discovery.resource(identity)
      )

    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "the discovered IAM issuer should be {string}", %{args: [issuer]} = context do
    body = Jason.decode!(context.last_conn.resp_body)
    assert body["links"] == [%{"rel" => LakehouseIam.Discovery.issuer_rel(), "href" => issuer}]
    :ok
  end
end
