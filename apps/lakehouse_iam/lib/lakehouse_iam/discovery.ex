defmodule LakehouseIam.Discovery do
  @moduledoc "WebFinger discovery for the Lakehouse PKCE protocol (RFC 7033)."
  alias LakehouseIam.{Identifier, Auth.CallbackURL}

  # This is a custom protocol relation, deliberately distinct from OpenID Connect.
  @issuer_rel "https://github.com/jeethsuresh/iam-server#issuer"
  def issuer_rel, do: @issuer_rel

  def public_url,
    do: Application.fetch_env!(:lakehouse_iam, :public_url) |> String.trim_trailing("/")

  def configuration(base \\ public_url()) do
    %{
      "issuer" => base,
      "identity_domain" => Identifier.domain(),
      "identifier_format" => "@username:domain",
      "backend_registration_endpoint" => base <> "/backend/register",
      "authorization_endpoint" => base <> "/oauth/authorize",
      "browser_initiation_endpoint" => base <> "/oauth/start",
      "registration_endpoint" => base <> "/register",
      "session_refresh_endpoint" => base <> "/refresh",
      "session_revocation_endpoint" => base <> "/revoke",
      "session_check_endpoint" => base <> "/oauth/session",
      "native_broker_authorization_endpoint" => base <> "/oauth/broker/authorize",
      "prompt_values_supported" => ["none"],
      "token_endpoint" => base <> "/oauth/token",
      "protocol_registry_endpoint" => base <> "/app/v1/protocols/registry",
      "protocol_specifications_endpoint" => base <> "/protocols/v1/specifications",
      "protocol_subscriptions_endpoint" => base <> "/protocols/v1/users/{subject}",
      "protocol_invocation_endpoint" => base <> "/protocols/v1/users/{subject}/invoke",
      "contacts_endpoint" => base <> "/app/v1/contacts",
      "contact_events_endpoint" => base <> "/app/v1/contacts/events",
      "userinfo_endpoint" => base <> "/app/v1/me",
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "code_challenge_methods_supported" => ["S256"],
      "scopes_supported" => LakehouseIam.Apps.Scopes.known()
    }
  end

  def webfinger(resource, rels \\ []) do
    with {:ok, identity} <- from_resource(resource),
         true <- identity.domain == Identifier.domain() do
      links = [%{"rel" => @issuer_rel, "href" => public_url()}]
      links = if rels == [], do: links, else: Enum.filter(links, &(&1["rel"] in rels))
      {:ok, %{"subject" => resource(identity), "links" => links}}
    else
      _ -> {:error, :not_found}
    end
  end

  def resource(identity), do: "acct:#{identity.username}@#{identity.domain}"

  def from_resource("acct:" <> account) do
    case String.split(account, "@", parts: 2) do
      [username, domain] -> Identifier.parse("@#{username}:#{domain}")
      _ -> {:error, :invalid_resource}
    end
  end

  def from_resource(input), do: Identifier.parse(input)

  @doc "Resolve @user:domain through WebFinger, including bounded HTTPS redirects."
  def resolve(input, opts \\ []) do
    fetch = Keyword.get(opts, :fetch, &request/1)
    validate = Keyword.get(opts, :validate, &validate_url/1)

    with {:ok, identity} <- Identifier.parse(input),
         scheme <- if(local_http?(identity.domain), do: "http", else: "https"),
         query <- URI.encode_query(%{"resource" => resource(identity), "rel" => @issuer_rel}),
         {:ok, finger} <-
           get_json(
             "#{scheme}://#{identity.domain}/.well-known/webfinger?#{query}",
             fetch,
             validate,
             5
           ),
         true <- finger["subject"] == resource(identity),
         {:ok, issuer} <- issuer_from_finger(finger),
         :ok <- validate_issuer(issuer),
         {:ok, metadata} <-
           get_json(issuer <> "/.well-known/iam-configuration", fetch, validate, 5),
         :ok <- validate_metadata(metadata, issuer, identity.domain, validate) do
      {:ok, identity, metadata}
    else
      {:error, _} = error -> error
      _ -> {:error, "identity discovery response does not match the requested identity"}
    end
  end

  defp issuer_from_finger(%{"links" => links}) when is_list(links) do
    case Enum.find(links, fn
           %{"rel" => @issuer_rel, "href" => href} when is_binary(href) -> true
           _ -> false
         end) do
      %{"href" => href} -> {:ok, href}
      _ -> {:error, "missing IAM issuer link"}
    end
  end

  defp issuer_from_finger(_), do: {:error, "invalid WebFinger links"}

  def validate_url(raw) when is_binary(raw) do
    uri = URI.parse(raw)

    cond do
      uri.userinfo != nil or uri.fragment != nil ->
        {:error, "discovery URL contains credentials or a fragment"}

      uri.scheme == "https" ->
        CallbackURL.validate(raw, "discovery URL")

      uri.scheme == "http" and local_http?(uri.host || "") ->
        CallbackURL.validate(raw, "discovery URL")

      true ->
        {:error, "discovery requires HTTPS (HTTP loopback is development-only)"}
    end
  end

  def validate_url(_), do: {:error, "invalid discovery URL"}

  defp validate_issuer(issuer) when is_binary(issuer) do
    case URI.parse(issuer) do
      %URI{host: host, path: path, query: nil, fragment: nil, userinfo: nil}
      when is_binary(host) and path in [nil, ""] ->
        :ok

      _ ->
        {:error, "issuer must be an origin without a path, query, fragment, or credentials"}
    end
  end

  defp validate_issuer(_), do: {:error, "missing issuer"}

  defp validate_metadata(metadata, issuer, domain, validate) do
    keys =
      ~w(backend_registration_endpoint authorization_endpoint token_endpoint userinfo_endpoint)

    if metadata["issuer"] == issuer and metadata["identity_domain"] == domain do
      Enum.reduce_while(keys, :ok, fn key, _ ->
        value = metadata[key]

        if is_binary(value) and URI.parse(value).scheme == URI.parse(issuer).scheme and
             URI.parse(value).authority == URI.parse(issuer).authority do
          case validate.(value) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
        else
          {:halt, {:error, "discovered endpoints must belong to the issuer"}}
        end
      end)
    else
      {:error, "discovered issuer or identity domain mismatch"}
    end
  end

  defp get_json(_url, _fetch, _validate, 0), do: {:error, "too many discovery redirects"}

  defp get_json(url, fetch, validate, remaining) do
    with :ok <- validate.(url), {:ok, response} <- fetch.(url) do
      cond do
        response.status == 200 and is_map(response.body) ->
          {:ok, response.body}

        response.status in [301, 302, 303, 307, 308] ->
          case Map.get(response.headers, "location", []) do
            [location | _] ->
              get_json(
                URI.merge(url, location) |> URI.to_string(),
                fetch,
                validate,
                remaining - 1
              )

            _ ->
              {:error, "discovery redirect is missing Location"}
          end

        true ->
          {:error, "identity discovery failed (HTTP #{response.status})"}
      end
    end
  end

  defp request(url),
    do:
      Req.get(url,
        redirect: false,
        retry: false,
        receive_timeout: 5_000,
        connect_options: [timeout: 5_000]
      )

  defp local_http?(domain) do
    Application.get_env(:lakehouse_iam, :relaxed_callback_urls, false) and
      URI.parse("http://" <> domain).host in ["localhost", "127.0.0.1", "::1"]
  end
end
