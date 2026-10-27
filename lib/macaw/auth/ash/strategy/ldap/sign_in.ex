defmodule Macaw.Auth.Ash.Strategy.Ldap.SignIn do
  @moduledoc """
  The LDAP strategy's sign-in action (`sign_in_with_<name>`): runs
  `Macaw.Auth.Ash.Strategy.Ldap.sign_in/4` and returns the user, with a
  user token in its `:token` metadata when the resource has tokens, as
  the password strategy's sign-in does (unless the action's context sets
  `token_type` to anything but `:user`).

  Every refusal is the same `AshAuthentication.Errors.AuthenticationFailed`,
  so neither AshAuthentication's plug nor an API built on the action tells
  a wrong password from an unknown user; the reason is in its `caused_by`,
  for logs.
  """

  use Ash.Resource.Actions.Implementation

  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias Macaw.Auth.Ash.Strategy.Ldap

  @impl true
  def run(input, _opts, context) do
    {:ok, strategy} = Info.strategy_for_action(input.resource, input.action.name)
    %{username: username, password: password} = input.arguments

    case Ldap.sign_in(strategy, username, password, []) do
      {:ok, record} ->
        {:ok, maybe_token(record, input.context[:token_type] || :user, context)}

      {:error, reason, _knows?} ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             reason: reason,
             message: Ldap.explain_refusal(reason)
           }
         )}
    end
  end

  defp maybe_token(record, :user, context) do
    if Info.authentication_tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} =
        Jwt.token_for_user(record, %{"purpose" => "user"}, Ash.Context.to_opts(context))

      Ash.Resource.put_metadata(record, :token, token)
    else
      record
    end
  end

  defp maybe_token(record, _type, _context), do: record
end
