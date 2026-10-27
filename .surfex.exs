# Surfex keeps this library's spec, tests and code aligned (macaw_compose spec/00 §4.1).
# Spec units are the spec's headings, identified by their `{#anchor}`; each carries its
# test hints. Code that predates the adoption was adopted by a baseline, its tests tagged
# one at a time against the units they verify (macaw_compose#65).
[
  sources: ["spec/*.md"],
  heading_ids: ~r/\{#(?<id>[a-z0-9-]+)\}\s*$/,
  tests: ["test/**/*_test.exs"],
  require: [code: [:implements, :excuses], test_hint: [:verifies]],
  adoption: :trust,
  # Type specs document the functions' contracts; the functions carry the relation
  # (a test can exercise a function, never a type).
  classes: [{"type", "types document the functions' contracts, which carry the relation"}],
  rules: [%{class: "type", kinds: [:type]}],
  # The index, and the sections marked `<!-- surfex: class orientation -->` (the overview's
  # descriptive ones, the token resource's introduction), describe the library; they assert
  # nothing a test checks. The overview's second-factor section states behavior, so it is not
  # classed. The limits' record of closed gaps is marked `<!-- surfex: class history -->`.
  spec_classes: [
    {"orientation",
     "describes what macaw_auth_ash holds, its versions and where it fits; asserts nothing a test checks",
     files: ["spec/README.md"]},
    {"history",
     "records the gaps found writing the spec and the releases that closed them; the sections it links state and verify the behavior"}
  ],
  # Units not built yet are deferred to their macaw_compose proposal (`<!-- surfex: deferred #N -->`);
  # `mix surfex.status --issues` asks macaw_compose whether it is still open.
  issues: [
    command: ["glab", "issue", "view", "{n}", "--repo", "{project}", "-F", "json"],
    state: "state",
    project: "dco-tek/macaw_compose"
  ]
]
