defmodule Macaw.Auth.Ash.ConformanceTest do
  # The kit, run against the Ash backend over the test app. The second
  # factor is pending, not passed by a stub: AshAuthentication 4.x has no
  # TOTP strategy.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Ash,
    fixtures: Macaw.Auth.Ash.Test.Fixtures,
    pending: [
      second_factor: "AshAuthentication 4.x has no TOTP strategy; supported when 5.0 is final"
    ]

  # The kit's tests are defined inside macaw_auth (`use` above), where no
  # source scan of this repository sees them; this test reads the ones this
  # module registered, so the run the spec describes is checked here. Each
  # of the seventeen passes or fails this same suite.
  @tag verifies: "ash-kit"
  test "the kit runs its seventeen tests here and holds its five second-factor tests pending" do
    kit =
      for test <- __MODULE__.__ex_unit__().tests,
          String.starts_with?(to_string(test.tags.describe), "conformance: "),
          do: test

    {pending, run} = Enum.split_with(kit, & &1.tags[:skip])
    assert length(run) == 17
    assert length(pending) == 5

    for test <- pending do
      assert test.tags.describe == "conformance: second factor"

      assert test.tags.skip ==
               "pending (second factor): AshAuthentication 4.x has no TOTP strategy; " <>
                 "supported when 5.0 is final"
    end
  end
end
