# Releasing OMC

OMC ships as the `omc` binary plus opt-in `node`/`npm`/`npx`/`pip`/`pip3`/
`python`/`python3`/`twine` compatibility shims. Releases are versioned with
SemVer and published to GitHub Releases. This repo builds the binaries and
publishes the Release; the Homebrew formula lives in the separate
`turenlabs/homebrew-tap` repo and is bumped there per release.

## Versioning

The workspace version in `Cargo.toml` (`[workspace.package].version`) is the
single source of truth; every crate inherits it and `omc --version` reports it.
Bump it, commit, then tag.

## Cutting a release

1. Update `CHANGELOG.md`: rename the `## [Unreleased]` heading to
   `## [<version>] - <YYYY-MM-DD>` (and add a fresh empty `## [Unreleased]`
   above it). The Release workflow uses this section as the GitHub Release body.
2. Bump `[workspace.package].version` in `Cargo.toml` (e.g. `0.1.1` → `0.2.0`),
   update `Cargo.lock` (`cargo update -p omc-cli` or `cargo build`), and commit.
3. Tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. The **Release** workflow (`.github/workflows/release.yml`) then:
   - builds `--release` binaries for `aarch64-apple-darwin`,
     `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
     `aarch64-unknown-linux-gnu` (native, on the GitHub arm runner), and the
     fully static `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`
     (for Alpine and `FROM scratch` containers; pure-Rust deps + ring, so
     `musl-tools` is the only extra toolchain piece);
   - packages each into `omc-<version>-<target>.tar.gz` (with `omc` at the root
     and the shims under `shims/`) AND a standalone `omc-<target>` single binary
     for direct download, each with a `.sha256`;
   - creates the GitHub Release with the tarballs, the standalone binaries, and a
     combined `SHA256SUMS` file.

   No token or extra secret is needed — the workflow only builds binaries and
   publishes the GitHub Release.

You can also trigger it manually from the Actions tab (`workflow_dispatch`) with
a `tag` input, without pushing a tag. Check the `dry_run` box to build and
package every target but skip publishing; use this to validate matrix changes
before tagging a real release:

```bash
gh workflow run release.yml -f tag=v0.3.0 -f dry_run=true
```

5. Bump the Homebrew formula in `turenlabs/homebrew-tap` (see below).

## Homebrew

The Homebrew formula is a **binary** formula — `brew install` downloads the
prebuilt `omc` release tarball for the user's platform and installs it (no
compile, no Rust toolchain). The formula lives in the separate
`turenlabs/homebrew-tap` repo, not here; this repo only builds the binaries and
publishes the GitHub Release. Users install via:

```bash
brew install turenlabs/tap/omc          # prebuilt binary, installs in seconds
# or build the latest main from source (needs Rust):
brew install --HEAD turenlabs/tap/omc
```

`brew install omc` installs only `omc` onto the PATH; it does **not** shadow the
system `node`/`npm`/`pip`/`python`. The shims are installed under the formula's
`libexec/shims` and enabled opt-in:

```bash
export PATH="$(brew --prefix omc)/libexec/shims:$PATH"
```

### Bumping the formula after a release

The formula is bumped in the `turenlabs/homebrew-tap` repo, manually, after the
GitHub Release exists. From a checkout of that tap, run its `bump-omc.sh` with
the new version; it fetches the release's `SHA256SUMS`, rewrites each platform's
prebuilt-tarball `url`/`sha256` and the `version`, and commits. No token or CI
job in this repo is involved.

## Local dry run

```bash
cargo build --release --locked --package omc-cli
scripts/package-release.sh 0.2.0 "$(rustc -vV | sed -n 's/host: //p')"  # use the version you're cutting
ls dist/
```

## Security default

Released binaries ship deny-by-default for reading sensitive files (`.ssh`,
`.env`, private keys, `.npmrc`/`.pypirc` tokens, cloud credentials, ...): a
wildcard `fs.read:*` grant (including `--allow-all-host`) does **not** cover
them. Override per-file with an exact `fs.read:<path>` grant, or globally with
`--allow-sensitive`.
