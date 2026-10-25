defmodule LakehouseMatrix.CrossSigning do
  @moduledoc "Public cross-signing identities and verified signatures. Private signing keys stay on clients."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.{DeviceKeys, Signing}
  @usages ~w(master self_signing user_signing)

  def keys(principal),
    do:
      Repo.all(
        from k in "matrix_cross_signing",
          where: k.principal_id == type(^principal, :binary_id),
          select: {k.usage, k.key}
      )
      |> Map.new()

  def upload(principal, params, authenticated \\ false) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      user = mxid(principal)
      old = keys(principal)

      supplied =
        for usage <- @usages,
            value = params[usage <> "_key"],
            not is_nil(value),
            into: %{},
            do: {usage, value}

      unless Enum.all?(supplied, fn {usage, key} -> valid?(key, user, usage) end),
        do: Repo.rollback(:invalid_param)

      changed = Enum.any?(supplied, fn {usage, key} -> bare(key) != bare(old[usage]) end)
      if old["master"] && changed && not authenticated, do: Repo.rollback(:reauth_required)
      master = supplied["master"] || old["master"]
      unless supplied == %{} or master, do: Repo.rollback(:invalid_param)

      for usage <- ~w(self_signing user_signing), key = supplied[usage], not is_nil(key) do
        unless signed_by?(key, master, user), do: Repo.rollback(:invalid_signature)
      end

      if supplied["master"] && bare(supplied["master"]) != bare(old["master"]) do
        Repo.delete_all(
          from k in "matrix_cross_signing", where: k.principal_id == type(^principal, :binary_id)
        )
      end

      for {usage, key} <- supplied do
        Repo.insert_all(
          "matrix_cross_signing",
          [%{principal_id: ClientStore.dump_id(principal), usage: usage, key: key}],
          on_conflict: [set: [key: key]],
          conflict_target: [:principal_id, :usage]
        )
      end

      if changed, do: DeviceKeys.signing_changed!(principal)
      %{}
    end)
  end

  def valid?(key, user, usage) when is_map(key) do
    key["user_id"] == user and key["usage"] == [usage] and is_map(key["keys"]) and
      map_size(key["keys"]) == 1 and
      Enum.all?(key["keys"], fn {id, encoded} ->
        is_binary(encoded) and id == "ed25519:" <> encoded and
          match?({:ok, <<_::256>>}, Base.decode64(encoded, padding: false))
      end) and byte_size(Jason.encode!(key)) <= 65_536
  rescue
    _ -> false
  end

  def valid?(_, _, _), do: false

  def signed_by?(object, key, user) when is_map(key) do
    Enum.any?(key["keys"] || %{}, fn {id, encoded} ->
      with {:ok, public} <- Base.decode64(encoded, padding: false),
           do: Signing.verify(object, public, id, user),
           else: (_ -> false)
    end)
  end

  def signed_by?(_, _, _), do: false

  def query(principal, user, requester) do
    keys = keys(principal)

    fields =
      [{"master_keys", "master"}, {"self_signing_keys", "self_signing"}] ++
        if requester == principal, do: [{"user_signing_keys", "user_signing"}], else: []

    for {field, usage} <- fields,
        key = keys[usage],
        not is_nil(key),
        into: %{},
        do: {field, %{user => decorate(key, user, key_id(key), requester)}}
  end

  def signatures(principal, params) when is_map(params) and map_size(params) <= 100 do
    Repo.transaction(fn ->
      ClientStore.lock!()
      signer = mxid(principal)
      own = keys(principal)

      failures =
        Enum.reduce(params, %{}, fn {user, targets}, acc ->
          if is_map(targets) and map_size(targets) <= 100 do
            Enum.reduce(targets, acc, fn {id, signed}, failed ->
              case verify_target(principal, signer, own, user, id, signed) do
                :ok ->
                  signatures = signed["signatures"][signer]

                  existing =
                    Repo.one(
                      from s in "matrix_key_signatures",
                        where:
                          s.principal_id == type(^principal, :binary_id) and
                            s.target_user == ^user and s.target_key == ^id,
                        select: s.signatures
                    ) || %{}

                  merged = Map.merge(existing, signatures)

                  Repo.insert_all(
                    "matrix_key_signatures",
                    [
                      %{
                        principal_id: ClientStore.dump_id(principal),
                        target_user: user,
                        target_key: id,
                        signatures: merged
                      }
                    ],
                    on_conflict: [set: [signatures: merged]],
                    conflict_target: [:principal_id, :target_user, :target_key]
                  )

                  failed

                _ ->
                  Map.update(
                    failed,
                    user,
                    %{id => signature_error()},
                    &Map.put(&1, id, signature_error())
                  )
              end
            end)
          else
            Map.put(acc, user, %{"" => signature_error()})
          end
        end)

      %{"failures" => failures}
    end)
  end

  def signatures(_, _), do: {:error, :invalid_param}

  def decorate(object, user, id, requester) do
    own =
      case Identity.parse_user_id(user) do
        {:ok, name} ->
          case Accounts.fetch_user(name) do
            {:ok, p} -> p.id
            _ -> nil
          end

        _ ->
          nil
      end

    principals =
      Enum.filter([own, if(is_binary(requester), do: requester)], &is_binary/1) |> Enum.uniq()

    rows =
      Repo.all(
        from s in "matrix_key_signatures",
          join: p in LakehouseIam.Schema.Principal,
          on: p.id == s.principal_id,
          where: s.target_user == ^user and s.target_key == ^id and p.id in ^principals,
          select: {p.username, s.signatures}
      )

    Enum.reduce(rows, object, fn {name, signatures}, key ->
      Map.update(key, "signatures", %{Identity.user_id(name) => signatures}, fn current ->
        Map.update(current, Identity.user_id(name), signatures, &Map.merge(&1, signatures))
      end)
    end)
  end

  defp verify_target(principal, signer, own, user, id, signed) when is_map(signed) do
    target = target(user, id)

    signing_keys =
      if user == signer do
        devices =
          Repo.all(
            from d in "matrix_devices",
              where: d.principal_id == type(^principal, :binary_id),
              select: d.keys
          )

        [own["self_signing"], own["master"] | devices]
      else
        [own["user_signing"]]
      end

    if (target && (user == signer or target["usage"] == ["master"]) &&
          bare(target) == bare(signed)) and
         Enum.any?(signing_keys, &signed_by?(signed, &1, signer)),
       do: :ok,
       else: {:error, :invalid_signature}
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp verify_target(_, _, _, _, _, _), do: {:error, :invalid_signature}

  defp target(user, id) do
    case Identity.parse_user_id(user) do
      {:ok, name} ->
        with {:ok, p} <- Accounts.fetch_user(name) do
          device =
            Repo.one(
              from d in "matrix_devices",
                where: d.principal_id == type(^p.id, :binary_id) and d.device_id == ^id,
                select: d.keys
            )

          device || Enum.find_value(keys(p.id), fn {_, key} -> if key_id(key) == id, do: key end)
        else
          _ -> nil
        end

      _ ->
        row =
          Repo.one(
            from u in "matrix_remote_users", where: u.user_id == ^user, select: u.master_key
          )

        if row && key_id(row) == id, do: row
    end
  end

  def key_id(key) when is_map(key), do: key["keys"] |> Map.values() |> List.first()
  def key_id(_), do: nil
  defp bare(value) when is_map(value), do: Map.drop(value, ["signatures", "unsigned"])
  defp bare(_), do: nil

  defp mxid(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  defp signature_error,
    do: %{
      "errcode" => "M_INVALID_SIGNATURE",
      "error" => "Invalid signature or unknown signing key"
    }
end
