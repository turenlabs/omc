# Releasing OMC

OMC ships as the `omc` binary plus opt-in `node`/`npm`/`npx`/`pip`/`pip3`/
`python`/`python3`/`twine` compatibility shims. Releases are versioned with
SemVer and published to GitHub Releases + a Homebrew tap.

## Versioning

The workspace version in `Cargo.toml` (`[workspace.package].version`) is the
single source of truth; every crate inherits it and `omc --version` reports it.
Bump it, commit, then tag.

## Cutting a release

1. Bump `[workspace.package].version` in `Cargo.toml` (e.g. `0.1.0` → `0.2.0`),
   update `Cargo.lock` (`cargo update -p omc-cli` or `cargo build`), and commit.
2. Tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. The **Release** workflow (`.github/workflows/release.yml`) then:
   - builds `--release` binaries for `aarch64-apple-darwin`,
     `x86_64-apple-darwin`, and `x86_64-unknown-linux-gnu`;
   - packages each into `omc-<version>-<target>.tar.gz` (with `omc` at the root
     and the shims under `shims/`) AND a standalone `omc-<target>` single binary
     for direct download, each with a `.sha256`;
   - creates the GitHub Release with the tarballs, the standalone binaries, and a
     combined `SHA256SUMS` file;
   - updates the Homebrew tap formula (only if configured — see below).

You can also trigger it manually from the Actions tab (`workflow_dispatch`) with
a `tag` input, without pushing a tag.

## Homebrew

The canonical formula lives at `Formula/omc.rb`. Users install via a tap:

```bash
brew tap turenio/omc https://github.com/turenio/omc
brew install omc
# or track main:
brew install --HEAD turenio/omc/omc
```

`brew install omc` installs only `omc` onto the PATH; it does **not** shadow the
system `node`/`npm`/`pip`/`python`. The shims are installed under the formula's
`libexec/shims` and enabled opt-in:

```bash
export PATH="$(brew --prefix omc)/libexec/shims:$PATH"
```

### Auto-publishing the formula to a dedicated tap (optional)

To have releases push the updated formula to a separate
`owner/homebrew-tap` repo, set in this repo's settings:

- Repository **variable** `HOMEBREW_TAP_REPO` = `turenio/homebrew-tap`
- Repository **secret** `HOMEBREW_TAP_TOKEN` = a PAT with write access to that tap

The `update-homebrew` job computes the tagged source tarball's sha256, rewrites
`Formula/omc.rb`'s `url`/`sha256`/`version`, and commits it to the tap. Without
those settings the job logs and exits 0, so releases never fail on a missing tap.

## Local dry run

```bash
cargo build --release --locked --package omc-cli
scripts/package-release.sh 0.2.0 "$(rustc -vV | sed -n 's/host: //p')"
ls dist/
```

## Security default

Released binaries ship deny-by-default for reading sensitive files (`.ssh`,
`.env`, private keys, `.npmrc`/`.pypirc` tokens, cloud credentials, ...): a
wildcard `fs.read:*` grant (including `--allow-all-host`) does **not** cover
them. Override per-file with an exact `fs.read:<path>` grant, or globally with
`--allow-sensitive`.
