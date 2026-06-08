# How OMC stops supply-chain worms

Worms like **Shai-Hulud** spread through the npm/PyPI graph using one mechanic:
**install-time code execution.** A compromised package ships a lifecycle hook
(`postinstall`, `prepare`, a `.pth` file, `sitecustomize.py`) that runs the
instant you install it — on a laptop or a CI runner — and:

1. **harvests credentials** — `~/.npmrc` tokens, `~/.aws/credentials`, cloud
   metadata, `process.env` / `os.environ`;
2. **exfiltrates** them to a webhook or a public repo it creates; and
3. **republishes** itself (and often trojanizes other packages the stolen token
   can publish), so the next victim's install spreads it further.

Every step depends on step 0: *the package's code ran during install.*

## OMC removes step 0

**OMC never runs a package's install scripts and never imports the package to
install it.** It resolves the package, downloads the archive, and compiles the
source to a small capability-typed bytecode. The verdict is computed by *reading*
the code, not running it. Concretely, for a Shai-Hulud-shaped package OMC blocks
on **any** of these, deny-by-default:

| Worm behaviour | What OMC sees | Default verdict |
| --- | --- | --- |
| `postinstall` / `prepare` hook | a `proc.spawn` capability (`npm-script:postinstall`) | **blocked** |
| `.pth` / `sitecustomize.py` startup hook | never copied into site-packages | **stripped** |
| reads `~/.npmrc` / `~/.aws/credentials` | a read of a **sensitive** path | **blocked even under `fs.read:*`** |
| obfuscated trigger (`process['en'+'v']`, `new Function(...)`) | a `dynamic.eval` capability | **blocked** |
| secret → network exfil | a `env→net` (or `file→net`) **data flow** | **blocked without a flow grant** |
| writes a backdoor / persistence file | an `fs.write` capability | **blocked** |

These are pinned by regression tests
(`shai_hulud_worm_is_blocked_at_install`, `obfuscated_shai_hulud_worm_is_blocked_at_install`,
and the red-team suite in `crates/omc-registry`), verified under OMC's *most
permissive* install posture.

## Install-time vs. runtime: why legit libraries still install clean

A library's **runtime** capabilities — the network calls, env reads, and file
reads it performs *when your application later calls it* — are not install-time
risks, because installing runs none of that code. OMC demotes those benign
capabilities to informational at the install gate, so `omc add lodash` or a
plain HTTP client installs without ceremony.

What stays deny-by-default is exactly the install-/malware-relevant set above:
process spawn (incl. lifecycle scripts), dynamic eval, file writes, sensitive
reads, and every **secret → sink flow**. So a package like `stripe`, which both
reads `STRIPE_API_KEY` and calls `api.stripe.com`, is gated on the *flow* (the
exfiltration shape), not on its individual capabilities — you authorize it once,
explicitly, in `omc.policy`:

```
npm package "stripe" >=12.0.0 {
  allow env "STRIPE_API_KEY"
  allow net "api.stripe.com"
  flow env "STRIPE_API_KEY" -> net "api.stripe.com"
}
```

The grant is the review checkpoint: a *newly* compromised `stripe` that started
reading `~/.ssh` or POSTing to a new host would block until someone widened the
policy — which is when a human looks.

## Freshness floor (catch the worm's launch window)

Worm releases are usually yanked within hours of discovery. Requiring a minimum
**release age** sidesteps that entire window — a version must have been public at
least that long to install.

**This floor is on by default.** With zero configuration OMC applies a built-in
**14-day** freshness floor, so a fresh malicious release is held back out of the
box. You don't have to opt in; you tune or disable it. To set a different floor
explicitly:

```toml
# ~/.omc/omc.toml  (or a project's omc.toml)
[policy]
min-release-age = "14d"   # this is also the built-in default if unset
```

Durations accept `14d` / `12h` / `2w` / `7` (a bare number means days) / `0`
(off). The floor is resolved most-specific-first, falling back to the built-in
default:

1. `omc.policy` `min-age` — per package;
2. project `omc.toml` `[policy] min-release-age`;
3. global `~/.omc/omc.toml` `min-release-age`;
4. **built-in 14-day default** — applied when none of the above is set.

An explicit `0` at any layer relaxes the floor for that scope: `min-release-age =
"0"` in an `omc.toml`, or `min-age "0"` in `omc.policy`, disables it (e.g. for a
specific dependency that genuinely needs a fresh release). Set a larger value
once globally and it applies under every project.

---

## Recipe: lock down a CI pipeline

The pipeline should resolve **nothing** at build time — it installs the exact
artifacts your lockfile already verified, then fails the build if any are blocked.

```yaml
# .github/workflows/ci.yml (excerpt)
steps:
  - uses: actions/checkout@v4

  - name: Install OMC
    run: |
      brew install turenlabs/tap/omc

  - name: Install from the lockfile (no registry resolution, no scripts)
    run: omc ci            # installs omc.lock exactly; never runs install scripts

  - name: Fail the build on any blocked dependency
    run: omc audit         # exits non-zero if any locked package is Blocked
```

- `omc ci` is the install equivalent of `npm ci` / `pip install --require-hashes`:
  it installs straight from `omc.lock` and resolves nothing, so a freshly
  published malicious version cannot enter on this run.
- `omc audit` (add `--json` for machine output) summarizes the locked graph and
  **exits non-zero if anything is blocked**, so a dependency that needs a grant
  fails the build loudly instead of silently running.
- Updating dependencies is a deliberate, reviewable step (`omc add …` / `omc
  install`) that happens in a PR, where the new grants and any `min-release-age`
  override are visible in the diff — not on every CI run. The 14-day freshness
  floor applies by default even with no `[policy]` block.

The built-in 14-day floor already applies on every runner. Commit a global
`omc.toml` into the runner image (or set `$OMC_HOME` to a checked-in config) when
you want to raise that floor or pin the same grant baseline across jobs. A starter
is in [`examples/omc.global.toml`](../examples/omc.global.toml).

## Recipe: a developer device

```bash
brew install turenlabs/tap/omc

# 1. One-time global baseline: org-wide freshness floor + deny-by-default.
mkdir -p ~/.omc && cp "$(brew --prefix omc)/share/omc/omc.global.toml" ~/.omc/omc.toml
#   (or copy examples/omc.global.toml from the repo)

# 2. Work in a project exactly like npm/pip — installs are verified, scripts never run.
omc add --npm left-pad@1.3.0
omc install

# 3. Run your code through OMC's shims: the REAL interpreter, isolated import path.
omc node app.js
omc python -m myapp
```

To make `node` / `npm` / `pip` / `python` route through OMC transparently, opt the
drop-in shims onto `PATH` (they are kept off by default so they don't shadow the
system tools):

```bash
export PATH="$(brew --prefix omc)/libexec/shims:$PATH"
```

Enforcement happens at **install** time — resolution, source profiling, and the
capability/flow/age verdicts above, with no install scripts ever run. The shims
then run your real interpreter against the project's isolated, already-verified
install tree; grants are recorded in `omc.lock`, so what each dependency is
allowed to do stays auditable.

---

- 🛡️ Policy DSL — complete reference: [POLICY.md](POLICY.md)
- 📖 Quickstart & full reference: [REFERENCE.md](REFERENCE.md)
- 🏗️ Architecture: [oss-microcode-runtime.md](oss-microcode-runtime.md)
