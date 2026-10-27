defmodule Macaw.Auth.Ash.TokenResource.Transformer do
  @moduledoc false
  # Runs after AshAuthentication's token transformer, whose actions it
  # extends, and before Ash's own action transformers, as AshAuthentication's
  # does.

  use Spark.Dsl.Transformer

  alias Ash.Resource
  alias AshAuthentication.TokenResource
  alias Spark.Dsl.Transformer

  @impl true
  def after?(TokenResource.Transformer), do: true
  def after?(_), do: false

  @impl true
  def before?(Resource.Transformers.CachePrimaryKey), do: true
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl) do
    revoke_all =
      TokenResource.Info.token_revocation_revoke_all_stored_for_subject_action_name!(dsl)

    primary_read? = Enum.any?(Resource.Info.actions(dsl), &(&1.type == :read and &1.primary?))

    with {:ok, dsl} <- maybe_add(dsl, :macaw_auth_read, :read, primary?: not primary_read?),
         {:ok, dsl} <- maybe_add(dsl, :macaw_auth_update, :update, accept: [:extra_data]),
         {:ok, dsl} <-
           maybe_add(dsl, :macaw_auth_revoke, :update,
             accept: [],
             changes: [
               Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
                 change:
                   {Ash.Resource.Change.SetAttribute, attribute: :purpose, value: "revocation"}
               )
             ]
           ) do
      {:ok,
       dsl
       |> announce_on(revoke_all)
       |> Transformer.persist(:macaw_auth_ash_token?, true)}
    end
  end

  defp maybe_add(dsl, name, type, opts) do
    if Resource.Info.action(dsl, name) do
      {:ok, dsl}
    else
      with {:ok, action} <-
             Transformer.build_entity(Resource.Dsl, [:actions], type, [name: name] ++ opts) do
        {:ok, Transformer.add_entity(dsl, [:actions], action)}
      end
    end
  end

  defp announce_on(dsl, action_name) do
    announce = Macaw.Auth.Ash.AnnounceRevocation

    case Resource.Info.action(dsl, action_name) do
      %{type: :update, changes: changes} = action ->
        if Enum.any?(changes, &match?(%{change: {^announce, _}}, &1)) do
          dsl
        else
          change =
            Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
              change: announce
            )

          Transformer.replace_entity(
            dsl,
            [:actions],
            %{action | changes: changes ++ [change]},
            &(&1.name == action_name)
          )
        end

      _ ->
        dsl
    end
  end
end
