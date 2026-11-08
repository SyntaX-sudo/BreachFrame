# Contributing to BreachFrame

Thanks for helping! Bug reports, rules, labs, docs and fixes are all welcome.

## Ground rules

- **Real behaviour only.** Every button and feature must do what it says. Do not
  add placeholder UI, sample data presented as real results, or claims in docs
  that were not verified.
- **Offline and non-executing.** The engine (`crates/engine`) must stay free of
  filesystem, network and process APIs. Never execute or fetch anything that
  appears in user input.
- **Secrets stay redacted.** Any new field that may carry credentials must go
  through `secrets::scan_*` / `util::redact`.
- **Tests with every change.** New rules need unit tests (positive *and*
  negative cases). New labs must pass `crates/engine/tests/labs.rs`.

## Development setup

See [docs/building.md](docs/building.md). Before opening a pull request, run:

```bash
npm run lint && npm run typecheck && npm test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Windows, please also run the desktop E2E suite (`npm run test:e2e`) when you
change the UI.

## Adding a rule

1. Implement it in the relevant module (`rbac.rs`, `iam.rs`, `mcp.rs`) using
   `FindingBuilder`. Give it a stable `key`, so fingerprints survive re-runs,
   plus clear description, impact, recommendation and evidence.
2. Add tests in the same file.
3. Document it in [docs/rules.md](docs/rules.md).

## Adding a lab

Labs are YAML files in `crates/engine/labs/` with `vulnerable` and `fixed`
variants. They are registered in `labs.rs`. The vulnerable variant must violate
at least one policy. The fixed variant must have no violations and nothing at
high severity or above.

## Commit and PR style

Small, focused PRs with a clear description of *what* and *why*. Update
`CHANGELOG.md` under *Unreleased* for user-visible changes.
