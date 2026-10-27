defimpl AshAuthentication.Strategy, for: Macaw.Auth.Ash.Strategy.Ldap do
  # The glue AshAuthentication's plug and router use: one phase, sign-in,
  # posted to /<subject>/<strategy> with the subject's params (`username`,
  # `password`), as the password strategy's sign-in is.

  alias Ash.ActionInput
  alias AshAuthentication.{Info, Plug.Helpers}

  def name(strategy), do: strategy.name

  def phases(_strategy), do: [:sign_in]

  def actions(_strategy), do: [:sign_in]

  def routes(strategy) do
    subject = Info.authentication_subject_name!(strategy.resource)
    [{"/#{subject}/#{strategy.name}", :sign_in}]
  end

  def method_for_phase(_strategy, :sign_in), do: :post

  def plug(strategy, :sign_in, conn) do
    subject = Info.authentication_subject_name!(strategy.resource)
    params = Map.get(conn.params, to_string(subject), %{})
    Helpers.store_authentication_result(conn, action(strategy, :sign_in, params, []))
  end

  def action(strategy, :sign_in, params, options) do
    {context, options} = Keyword.pop(options, :context, %{})

    strategy.resource
    |> ActionInput.new()
    |> ActionInput.set_context(
      Map.merge(Map.new(context), %{private: %{ash_authentication?: true}})
    )
    |> ActionInput.for_action(strategy.sign_in_action_name, params)
    |> Ash.run_action(
      Keyword.put_new_lazy(options, :domain, fn -> Info.domain!(strategy.resource) end)
    )
  end

  def tokens_required?(_strategy), do: false
end
