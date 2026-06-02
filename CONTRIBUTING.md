# Contributing to omc

Thanks for your interest in improving omc. omc is a deny-by-default supply-chain
security tool, so contributions are held to a high bar for correctness and for
never weakening an existing defense.

## Building and Testing

omc is a Rust workspace. Build and test the whole workspace:

```sh
cargo build --workspace
cargo test --workspace
```

If you only touched a single crate you may scope the commands to that crate
(e.g. `cargo test -p omc-registry`), but run the full workspace tests before
opening a PR if your change spans multiple crates.

## Formatting and Lints

Before committing, your change must pass:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
```

`cargo fmt --all` must leave no diff, and clippy must be free of warnings on the
code you touched.

## Tests and Fixtures

- Tests must use **canary hosts and placeholder values only** (e.g.
  `evil.invalid`, `canary.invalid`). Never commit real secrets, credentials, or
  live exploit payloads.
- When you change detection or verification behavior, add a test that fails
  before your change and passes after it.

## Pull Request Workflow

1. Branch off `main`.
2. Make your change, keeping it focused.
3. Ensure `cargo fmt --all`, `cargo build --workspace`, and
   `cargo test --workspace` all succeed locally.
4. Open a PR. CI runs build, format, clippy, and tests; **all checks must be
   green before merge.**
5. Address review feedback and keep the branch up to date with `main`.

## Leave Green or Revert

The tree is always kept green. If you cannot get `cargo fmt`, `cargo build`, and
`cargo test` passing for the crates you touched, **revert your changes** rather
than committing a broken state. Never commit a red tree.

## Security-Sensitive Changes

omc is deny-by-default. A change to the profiler, verifier, or verdict gate may
only ever catch **more**, never less. If you believe a defense should be relaxed,
open an issue to discuss it first — do not weaken a check in a PR.

For reporting vulnerabilities, see [SECURITY.md](SECURITY.md). Do not file
security issues as public PRs or issues.
