defmodule Macaw.Auth.Ash.Test.Migration do
  @moduledoc """
  The test app's tables, written by hand: `users` for the user resource
  and `tokens` as AshAuthentication's token resource needs it (`jti` the
  primary key, `extra_data` a JSON map).
  """

  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:username, :text, null: false)
      add(:hashed_password, :text)
      add(:display_name, :text)
      add(:roles, {:array, :text}, null: false, default: "[]")
      add(:source, :text, null: false, default: "local")
      add(:disabled_at, :utc_datetime_usec)
    end

    create(unique_index(:users, [:username], name: "users_unique_username_index"))

    create table(:tokens, primary_key: false) do
      add(:jti, :text, primary_key: true)
      add(:subject, :text, null: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:purpose, :text, null: false)
      add(:extra_data, :map)
      add(:created_at, :utc_datetime_usec, null: false)
      add(:updated_at, :utc_datetime_usec, null: false)
    end
  end
end
