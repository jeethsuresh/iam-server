defmodule LakehouseIam.Schema.Service do
  use Ecto.Schema
  import Ecto.Changeset
  alias LakehouseIam.Apps.Origin

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "services" do
    field :name, :string
    field :description, :string
    field :logo_url, :string
    field :home_url, :string
    field :login_url, :string
    field :origin, :string
    timestamps(type: :utc_datetime_usec)
  end

  def changeset(service, attrs) do
    service
    |> cast(attrs, [:name, :description, :logo_url, :home_url, :login_url])
    |> validate_required([:name, :description, :logo_url, :home_url, :login_url])
    |> validate_length(:name, max: 80)
    |> validate_format(:name, ~r/\p{L}/u, message: "must be a human-readable app name")
    |> validate_change(:name, fn :name, name ->
      if Regex.match?(~r{://|\A[a-z0-9-]+(?:\.[a-z0-9-]+)+/?\z}i, name),
        do: [name: "must be a name, separate from the service URL"],
        else: []
    end)
    |> validate_length(:description, max: 240)
    |> validate_length(:home_url, max: 2048)
    |> validate_length(:login_url, max: 2048)
    |> validate_length(:logo_url, max: 2048)
    |> validate_urls()
    |> validate_logo()
    |> unique_constraint(:origin)
  end

  defp validate_urls(changeset) do
    home = get_field(changeset, :home_url)
    login = get_field(changeset, :login_url)

    changeset =
      Enum.reduce([home_url: home, login_url: login], changeset, fn {field, url}, cs ->
        if valid_url?(url),
          do: cs,
          else: add_error(cs, field, "must be an HTTPS URL without credentials or a fragment")
      end)

    if valid_url?(home) and valid_url?(login) do
      if Origin.same_origin?(home, login) do
        {:ok, origin} = Origin.from_url(home)
        put_change(changeset, :origin, origin)
      else
        add_error(changeset, :login_url, "must use the same origin as the service URL")
      end
    else
      changeset
    end
  end

  defp validate_logo(changeset) do
    logo = get_field(changeset, :logo_url)
    home = get_field(changeset, :home_url)

    if is_binary(logo) and
         (Regex.match?(~r{\A/images/services/[a-z0-9-]+\.(svg|png)\z}, logo) or
            (valid_url?(logo) and valid_url?(home) and Origin.same_origin?(home, logo) and
               is_nil(URI.parse(logo).query))) do
      changeset
    else
      add_error(changeset, :logo_url, "must be a bundled image or an HTTPS image URL on the service origin without a query")
    end
  end

  defp valid_url?(url) when is_binary(url) do
    uri = URI.parse(url)
    dev = Application.get_env(:lakehouse_iam, :relaxed_callback_urls, false)

    scheme_ok =
      uri.scheme == "https" or
        (dev and uri.scheme == "http" and uri.host in ["localhost", "127.0.0.1", "::1"])

    scheme_ok and is_binary(uri.host) and uri.host != "" and is_nil(uri.userinfo) and
      is_nil(uri.fragment) and not Regex.match?(~r/[\s\\]/, url)
  rescue
    _ -> false
  end

  defp valid_url?(_), do: false
end
