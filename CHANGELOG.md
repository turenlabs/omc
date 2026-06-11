# Changelog

All notable changes to OMC are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and OMC follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`omc scan`**: read-only capability scan of an existing project, no
  migration needed. It reads the manifests and lockfiles the project already
  has (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml,
  requirements.txt, Pipfile.lock, uv.lock, poetry.lock, pyproject.toml, and
  more), profiles every declared package through the deny-by-default engine,
  and reports the verdicts without writing anything to the project. Exits `2`
  when any package would be blocked, so it works as a CI gate on projects that
  still install with plain npm or pip. Supports `--json` and `--omit-dev`.
- **`omc diff <old> <new>`**: the upgrade escalation check. Profiles two
  package versions and reports what changed: capabilities added or removed
  (with the evidence file for each), dependencies added, removed, or
  version-changed, and the verdict on each side. `--json` output includes an
  `escalation` boolean for gating dependency-bump PRs.

## [0.1.2] - 2026-06-08

### Fixed

- **npm version-range resolution** for two common forms that broke real
  dependency trees (Express, React/Vite resolved to "could not resolve a
  version"): whitespace-separated comparators with a space after the operator
  (`>= 2.1.2 < 3`), and caret ranges anchored on a prerelease (`^1.0.0-beta.2`,
  whose prerelease was dropped so the only published version never matched).

### Changed

- **Homebrew is now a binary install.** `brew install turenlabs/tap/omc`
  downloads the prebuilt `omc` release binary for your platform and installs it
  in seconds — no compile, no Rust toolchain. `brew install --HEAD` still builds
  from source. The formula now lives solely in the `turenlabs/homebrew-tap` repo;
  this repo only builds the binaries and publishes the GitHub Release.

## [0.1.1] - 2026-06-08

### Added

- **Supply-chain freshness on by default.** A built-in 14-day `min-release-age`
  floor now applies even with no configuration: a package version must have been
  published at least 14 days ago to install (defends against malware published
  moments before you install, e.g. account-takeover worms). Override per package
  (`omc.policy` `min-age`), per project (`omc.toml`), or globally
  (`~/.omc/omc.toml`); set `0` at any layer to disable it.

### Fixed

- CI `cargo fmt --check` failure on the CLI-cleanup edits (formatting only).

### Docs

- Richer terminal demo (`docs/demo.gif`) in the README.

## [0.1.0] - 2026-06-08

Initial public release.

### Added

- **Deny-by-default package manager for npm and PyPI.** Resolves dependencies,
  profiles their source, and verifies them against a capability/data-flow policy
  before locking — and **never runs install/postinstall scripts** (or Python
  `.pth`/`sitecustomize` startup hooks).
- **Capability + data-flow enforcement.** Env reads, file reads/writes, network,
  process spawn, and dynamic eval are denied by default; data-flow rules (e.g.
  `env -> network`) require explicit grants. Reading sensitive files (`~/.ssh`,
  `.env`, keys, `.npmrc`/`.pypirc` tokens, cloud creds) stays blocked even under
  `--allow-all-host`.
- **Per-package policy.** An optional `omc.policy` DSL scopes grants to individual
  packages (allow/deny/flow/pure/min-age), alongside project and global
  `omc.toml` policy. Grants are explicit and recorded in `omc.lock`.
- **npm / pip / twine compatibility** surfaces and opt-in drop-in shims, plus the
  native `omc add` / `install` / `ci` / `remove` commands.
- **Read-only `omc inspect`** capability report (text, or `--format png`
  dependency graph) and `omc audit` as a CI gate.
- **Distribution:** Homebrew via the public `turenlabs/homebrew-tap`, plus
  per-platform release binaries (macOS arm64/x86_64, Linux x86_64) with
  `SHA256SUMS`.

[Unreleased]: https://github.com/turenlabs/omc/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/turenlabs/omc/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/turenlabs/omc/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/turenlabs/omc/releases/tag/v0.1.0
