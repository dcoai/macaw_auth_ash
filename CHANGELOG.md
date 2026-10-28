# Changelog

## v0.3.3 (2026-10-28)

- Tests check that a refusal spends a hash by the verifications that run, never by timing two runs, and a test forbids timing in `test/` (#1).

## v0.3.2 (2026-10-28)

- The macaw logo in the docs and the README (macaw#175).
- CI: the LDAP fixture image moved with the server, now Collpa: `dco-tek/macaw/collpa/ci-ldap` (collpa#146).

## v0.3.1 (2026-10-28)

- On Hex: depends on `macaw_auth ~> 0.4.1` from Hex instead of its git tag; the README installs from Hex (macaw#155).
- The README opens with the early-release notice (macaw#174).
- Package metadata for Hex: the public home, the changelog link, the files shipped, and docs with `ex_doc` (macaw_compose#155).

## v0.3.0 (2026-10-27)

- check_config!/0 at boot; onto macaw_auth v0.4.0; v0.3.0

## v0.2.1 (2026-10-27)

- misconfigurations refused at Config load; v0.2.1

## v0.2.0 (2026-10-27)

- onto macaw_auth v0.2.0; v0.2.0

## v0.1.1 (2026-10-27)

- throttle, token-lifetime and idle_days checks, deleted-user refusal

## v0.1.0 (2026-10-27)

- macaw_auth_ash 0.1.0: macaw_auth over AshAuthentication 4.15, and the LDAP strategy
