defmodule Macaw.Auth.Ash.PlugTest do
  @moduledoc "macaw_auth's plugs over this backend: a session cookie's token resolves to its user."

  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias Macaw.Auth
  alias Macaw.Auth.Ash.Test.Fixtures
  alias Macaw.Auth.Plug, as: AuthPlug

  setup do
    :ok = Fixtures.reset!()
  end

  defp request(path, session) do
    conn(:get, path)
    |> init_test_session(session)
    |> AuthPlug.fetch_current_user([])
    |> AuthPlug.require_authenticated([])
  end

  test "a signed-in user passes, with user, session and no pending step" do
    {_user, creds} = Fixtures.user!(%{roles: ["admin"]})
    {:ok, user} = Auth.authenticate(creds)
    {:ok, token, session} = Auth.create_session(user, remote_ip: "203.0.113.7")

    conn = request("/reports", %{AuthPlug.token_key() => token})

    refute conn.halted
    assert conn.assigns.current_user.id == user.id
    assert conn.assigns.current_user.roles == ["admin"]
    assert conn.assigns.current_session.id == session.id
    assert conn.assigns.current_session.remote_ip == "203.0.113.7"
    assert conn.assigns.pending_step == nil
  end

  test "a revoked session is signed out, and sent to sign in" do
    {user, _} = Fixtures.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    :ok = Auth.revoke(session.id)

    conn = request("/reports", %{AuthPlug.token_key() => token})

    assert conn.halted and conn.status == 302
    assert conn |> get_resp_header("location") |> List.first() == "/login"
    assert conn.assigns.current_user == nil
    assert get_session(conn, AuthPlug.token_key()) == nil
  end

  test "signing in a user deleted since authenticating goes back to sign in, touching nothing" do
    {_user, creds} = Fixtures.user!(%{})
    {:ok, user} = Auth.authenticate(creds)
    :ok = Fixtures.delete!(user)

    conn =
      conn(:post, "/login")
      |> init_test_session(%{"kept" => "as it was"})
      |> Phoenix.Controller.fetch_flash([])
      |> AuthPlug.log_in(user, remember: true)

    assert conn.status == 302
    assert conn |> get_resp_header("location") |> List.first() == "/login"
    assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You could not be signed in."
    assert get_session(conn, AuthPlug.token_key()) == nil
    assert get_session(conn, "kept") == "as it was"
    refute Map.has_key?(conn.resp_cookies, AuthPlug.remember_cookie())
    assert Auth.list_sessions(user.id) == []
  end
end
