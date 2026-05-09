defmodule LakehouseIam.IAM do
  @moduledoc """
  Facade for authorization APIs (`IAM.can?`, role assignment, introspection).
  """

  alias LakehouseIam.Authorization

  defdelegate can?(principal_id, action, resource_arn), to: Authorization

  defdelegate assign_role(principal_id, role_name, resource_arn \\ nil), to: Authorization

  defdelegate revoke_role(principal_id, role_name, resource_arn \\ nil), to: Authorization

  defdelegate permissions_for(principal_id), to: Authorization

  defdelegate roles_for(principal_id), to: Authorization

  defdelegate resources_for(principal_id), to: Authorization
end
