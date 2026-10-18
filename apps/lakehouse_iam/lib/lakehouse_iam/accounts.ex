defmodule LakehouseIam.Accounts do
  @moduledoc """
  User-facing identity operations aligned with iam-server username rules.
  """
  import Ecto.Query

  alias LakehouseIam.{Identifier, Repo}
  alias LakehouseIam.Schema.{Credential, Principal}

  @max_username 20
  @max_password 1024

  @spec normalize_username(String.t()) :: String.t()
  def normalize_username(username) when is_binary(username) do
    case Identifier.local_username(String.trim(username)) do
      {:ok, local} -> local
      {:error, _} -> username |> String.trim() |> String.downcase()
    end
  end

  @spec validate_signup_username(String.t()) :: :ok | {:error, String.t()}
  def validate_signup_username(username) do
    trimmed = normalize_username(username)

    cond do
      trimmed == "" ->
        {:error, "username is required"}

      String.length(trimmed) > @max_username ->
        {:error, "username must be at most 20 characters"}

      not Regex.match?(~r/^[a-zA-Z0-9]+$/, trimmed) ->
        {:error, "username must contain only letters and numbers"}

      true ->
        :ok
    end
  end

  @spec validate_login_form(String.t(), String.t()) :: :ok | {:error, String.t()}
  def validate_login_form(username, password) do
    if String.trim(username) == "" or String.trim(password) == "" do
      {:error, "username and password are required"}
    else
      with {:ok, _local} <- Identifier.local_username(String.trim(username)) do
        if String.length(password) > @max_password do
          {:error, "username or password too long"}
        else
          :ok
        end
      end
    end
  end

  @spec register_user(String.t(), String.t(), keyword()) ::
          {:ok, Principal.t()} | {:error, Ecto.Changeset.t() | String.t()}
  def register_user(username, password, opts \\ [])
      when is_binary(username) and is_binary(password) do
    approve = Keyword.get(opts, :approve, false)
    canonical = normalize_username(username)

    with :ok <- validate_signup_username(username),
         :ok <- validate_login_form(canonical, password) do
      if user_exists?(canonical) do
        {:error, "username already taken"}
      else
        active = approve or admin_username?(canonical)

        principal_cs =
          %Principal{}
          |> Principal.registration_changeset(%{type: :user, username: canonical, active: active})

        hash = Argon2.hash_pwd_salt(password)

        cred_cs = fn pid ->
          %Credential{}
          |> Credential.changeset(%{
            kind: :password,
            secret_hash: hash,
            principal_id: pid
          })
        end

        Ecto.Multi.new()
        |> Ecto.Multi.insert(:principal, principal_cs)
        |> Ecto.Multi.insert(:credential, fn %{principal: p} -> cred_cs.(p.id) end)
        |> Repo.transaction()
        |> case do
          {:ok, %{principal: p}} ->
            if active, do: _ = LakehouseIam.IAM.assign_role(p.id, "member")
            {:ok, p}

          {:error, _step, cs, _} ->
            {:error, cs}
        end
      end
    end
  end

  defp admin_username?(canonical) do
    admin = Application.fetch_env!(:lakehouse_iam, :admin_username) |> normalize_username()
    canonical == admin
  end

  @doc """
  True when `username` is the configured bootstrap admin (`IAM_ADMIN_USERNAME`), case-insensitive.
  """
  @spec admin?(String.t()) :: boolean()
  def admin?(username) when is_binary(username) do
    admin_username?(normalize_username(username))
  end

  @doc """
  Users with `active: false` awaiting admin approval.
  """
  @spec list_pending_users() :: [Principal.t()]
  def list_pending_users do
    Repo.all(
      from p in Principal,
        where: p.type == :user and p.active == false,
        order_by: [asc: p.inserted_at]
    )
  end

  @doc """
  Activates a user account. Only the configured admin may call this successfully.
  """
  @spec approve_user(String.t(), String.t()) ::
          {:ok, Principal.t()} | {:error, :forbidden | :not_found}
  def approve_user(actor_username, target_username)
      when is_binary(actor_username) and is_binary(target_username) do
    actor = normalize_username(actor_username)
    target = normalize_username(target_username)

    if admin?(actor) do
      case fetch_user(target) do
        :error ->
          {:error, :not_found}

        {:ok, %Principal{active: true, id: id} = p} ->
          _ = LakehouseIam.IAM.assign_role(id, "member")
          {:ok, p}

        {:ok, %Principal{id: id}} ->
          case set_active(id, true) do
            {:ok, p} ->
              _ = LakehouseIam.IAM.assign_role(id, "member")
              {:ok, p}

            {:error, _} ->
              {:error, :not_found}
          end
      end
    else
      {:error, :forbidden}
    end
  end

  @doc """
  Change password for the signed-in user. Bootstrap admin cannot use this when
  `IAM_ADMIN_PASSWORD` is set (matches iam-server: restart with new env instead).
  """
  @spec change_own_password(String.t(), String.t(), String.t(), String.t()) ::
          :ok | {:error, term()}
  def change_own_password(username, current_password, new_password, new_password_confirm)
      when is_binary(username) do
    canonical = normalize_username(username)
    current_password = current_password || ""
    new_password = new_password || ""
    new_password_confirm = new_password_confirm || ""

    with :ok <-
           validate_password_change_form(current_password, new_password, new_password_confirm) do
      if admin?(canonical) and bootstrap_admin_password_set?() do
        {:error, :forbidden,
         "The admin password is set with IAM_ADMIN_PASSWORD when the server starts. Restart with a new value to change it."}
      else
        case fetch_user(canonical) do
          :error ->
            {:error, :not_found, "Account not found"}

          {:ok, principal} ->
            if password_valid?(canonical, current_password) do
              case set_password(principal.id, new_password) do
                :ok -> :ok
                {:error, _} -> {:error, :internal_server_error, "Could not update password"}
              end
            else
              {:error, :unauthorized, "Current password is incorrect."}
            end
        end
      end
    end
  end

  defp bootstrap_admin_password_set? do
    Application.fetch_env!(:lakehouse_iam, :admin_password) |> String.trim() != ""
  end

  defp validate_password_change_form(current, new, confirm) do
    cond do
      String.trim(current) == "" or String.trim(new) == "" ->
        {:error, :bad_request, "current and new password are required"}

      new != confirm ->
        {:error, :bad_request, "new passwords do not match"}

      String.length(new) > @max_password ->
        {:error, :bad_request, "new password too long"}

      true ->
        :ok
    end
  end

  @spec user_exists?(String.t()) :: boolean()
  def user_exists?(canonical_username) do
    Repo.exists?(
      from p in Principal, where: p.username == ^canonical_username and p.type == :user
    )
  end

  @spec fetch_user(String.t()) :: {:ok, Principal.t()} | :error
  def fetch_user(canonical_username) do
    case Repo.one(
           from p in Principal, where: p.username == ^canonical_username and p.type == :user
         ) do
      nil -> :error
      p -> {:ok, p}
    end
  end

  @spec active?(Principal.t()) :: boolean()
  def active?(%Principal{active: a}), do: a

  @spec password_valid?(String.t(), String.t()) :: boolean()
  def password_valid?(canonical_username, password) do
    admin_user = Application.fetch_env!(:lakehouse_iam, :admin_username) |> normalize_username()
    admin_pass = Application.fetch_env!(:lakehouse_iam, :admin_password) |> String.trim()

    cond do
      canonical_username == admin_user and admin_pass != "" ->
        secure_compare(password, admin_pass)

      true ->
        case fetch_password_credential(canonical_username) do
          nil -> false
          %Credential{secret_hash: hash} -> Argon2.verify_pass(password, hash)
        end
    end
  end

  defp fetch_password_credential(canonical_username) do
    Repo.one(
      from c in Credential,
        join: p in Principal,
        on: c.principal_id == p.id,
        where: p.username == ^canonical_username and p.type == :user and c.kind == :password,
        select: c
    )
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    if byte_size(a) != byte_size(b) do
      false
    else
      Enum.zip_reduce(:binary.bin_to_list(a), :binary.bin_to_list(b), 0, fn x, y, acc ->
        Bitwise.bxor(x, y) |> Bitwise.bor(acc)
      end) == 0
    end
  end

  @spec set_password(Ecto.UUID.t(), String.t()) :: :ok | {:error, term()}
  def set_password(principal_id, password) when is_binary(password) do
    hash = Argon2.hash_pwd_salt(password)

    case Repo.one(
           from c in Credential,
             where: c.principal_id == ^principal_id and c.kind == :password
         ) do
      nil ->
        %Credential{}
        |> Credential.changeset(%{kind: :password, secret_hash: hash, principal_id: principal_id})
        |> Repo.insert()

      cred ->
        cred
        |> Credential.changeset(%{secret_hash: hash})
        |> Repo.update()
    end
    |> case do
      {:ok, _} -> :ok
      {:error, cs} -> {:error, cs}
    end
  end

  @spec set_active(Ecto.UUID.t(), boolean()) ::
          {:ok, Principal.t()} | {:error, Ecto.Changeset.t()}
  def set_active(principal_id, active) do
    case Repo.get(Principal, principal_id) do
      nil ->
        {:error, %Ecto.Changeset{}}

      p ->
        p
        |> Ecto.Changeset.change(active: active)
        |> Repo.update()
    end
  end
end
