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
end
