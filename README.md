# OMC

**A drop-in `npm`/`pip` that never runs install scripts and won't let packages touch your secrets.**

Packages don't execute as JavaScript or Python when you install them. OMC resolves them, compiles their code to a small **verified bytecode**, and denies anything dangerous **by default** — reading env vars, files, the network, spawning processes. Reading sensitive files (`~/.ssh`, `.env`, keys, tokens) stays blocked *even with* `--allow-all-host`. Access is granted explicitly, per package, and recorded.

```bash
brew tap turenio/omc https://github.com/turenio/omc && brew install omc

omc init --name myapp                  # new project
omc add --npm left-pad@1.3.0           # resolve + verify — no install scripts run
omc install                            # or: install straight from package.json / requirements.txt
```

A package that wants host access is **blocked** until you allow it:

```bash
omc add --npm esbuild@0.19.12                       # ✗ blocked (postinstall + network)
omc add --npm esbuild@0.19.12 --allow http:registry.npmjs.org   # ✓ allowed + recorded
```

That's the whole idea: **dependencies are behavior-typed artifacts, not trusted code.**

## Using what you install

Installed packages work normally — you just run them through OMC, which uses the
project's own isolated install tree (`node_modules` / `.omc/python/site-packages`):

```bash
omc add --pypi requests==2.32.3 --allow-all-host   # grant it (requests does network)
omc python -c "import requests; print(requests.get('https://example.com').status_code)"

omc add --npm is-odd@3.0.1
omc node -e "console.log(require('is-odd')(3))"
```

The `omc node` / `omc python` commands (and the drop-in `node`/`npm`/`pip`/`python`
shim names, opt-in on `PATH`) run your **real** interpreter with an isolated import
path. So `import requests` and `requests.get(...)` behave exactly like normal —
**OMC's enforcement happens at install time** (resolution, source profiling,
capability/flow/age verdicts, no install scripts), not as a runtime sandbox
around host-run code. Grants are recorded in `omc.lock`, so what each dependency
is allowed to do is auditable.

> Scope today: pure-Python wheels/sdists and npm packages. Packages that need a
> **native build** (C extensions like `numpy`/`cryptography` from source) aren't
> built yet — a sandboxed build chain with secure defaults is the natural next
> step.

## Per-package policy (`omc.policy`)

`omc.toml`'s `[policy]` block is one flat allow-list for the whole project. Drop an optional **`omc.policy`** file next to it to scope grants to *individual* packages — a `default` baseline plus `package` blocks that `allow`/`deny` capabilities, declare `flow`s, mark a package `pure`, or lift the sensitive-read guard:

```
# omc.policy
default {
  allow time, random                   # baseline for every package
  min-age "14d"                         # ...and reject versions published < 14d ago
}
package "is-odd" { pure }                # zero host capabilities
npm package "stripe" >=12.0.0 {         # ecosystem + version-scoped
  allow env "STRIPE_API_KEY"
  allow net "api.stripe.com"
  flow env "STRIPE_API_KEY" -> net "api.stripe.com"
}
package "trusted-internal" { min-age "0" }  # exempt from the age floor
npm package "@acme/*" { allow net "*" }  # name globs
```

Each dependency is verified against *its* block (deny-by-default: no match means no grants). The `omc.toml` `[policy]` grants still apply as part of the baseline, so existing projects keep working unchanged. Inspect and validate it:

```bash
omc policy validate                      # parse omc.policy; OK or a located error
omc policy check stripe@13.1.0           # show the effective compiled policy
omc policy list                          # list global accepted package grants
```

### Package-age checks (supply-chain freshness)

To block just-published malware, require a minimum **release age** — a version must have been published at least that long ago to install. Set it per-package in `omc.policy` (`min-age`), or project-wide in `omc.toml`:

```toml
[policy]
min-release-age = "14d"     # 14d / 12h / 2w / 7 (days) / 0 (off)
```

### Global policy (`~/.omc/omc.toml`)

OMC also reads a **global** user policy at `~/.omc/omc.toml` (override the dir with `$OMC_HOME`). Its `[policy]` grants are unioned under every project as a baseline, and its `min-release-age` is the fallback floor a project can override. Use it to set an org-wide freshness floor or default grants once:

```toml
# ~/.omc/omc.toml
[policy]
min-release-age = "7d"
```

### Granting a package everywhere (`~/.omc/policy.d/` + `omc policy grant`)

When a package is blocked, `omc add <spec>` opens a guided prompt:
`[y] once`, `[a] always`, or `[N] deny`. Choosing always writes a
**per-package, version-pinned** trust that applies in every project. The manual
equivalent is:

```bash
omc policy grant pypi:requests@2.32.5 --allow-flow 'env:*->network:*' --allow dynamic.eval
```

This writes a drop-in `~/.omc/policy.d/requests.omc.policy` (a directory of
per-package `omc.policy` blocks). Each block grants **only** its exact
package+version, so a trust decision never leaks to other packages or to
transitive dependencies — unlike a flat project-wide grant. Delete the file to
revoke. Hand-authored files in `~/.omc/policy.d/` work too. Run `omc policy
list` (or `omc policy list global`) to inspect those global accepts.

**Every field, statement, capability, flow, version operator, and the
project/global config — see [docs/POLICY.md](docs/POLICY.md).**

## Stopping supply-chain worms (Shai-Hulud)

Worms like Shai-Hulud spread through one mechanic: **install-time code execution**
— a `postinstall` hook (or `.pth` / `sitecustomize.py`) that runs the moment you
install, harvests `~/.npmrc`/cloud creds/env, exfiltrates them, and republishes
itself. OMC removes that mechanic: it **never runs install scripts** and never
imports a package to install it — it compiles the source and computes the verdict
by *reading* it. A lifecycle hook surfaces as a blocked `proc.spawn`; obfuscated
triggers as `dynamic.eval`; reads of `~/.npmrc`/`~/.aws` stay blocked even under
`fs.read:*`; and any secret → network **flow** is denied without an explicit
grant. Add a `min-release-age` floor to skip the window where a malicious release
is live but not yet yanked. Pinned by regression tests
(`shai_hulud_worm_is_blocked_at_install`).

**Threat model, CI recipe (`omc ci` + `omc audit`), and dev setup — see
[docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md).** A recommended global config is in
[`examples/omc.global.toml`](examples/omc.global.toml).

---

- 📖 **[Quickstart & full reference →](docs/REFERENCE.md)**
- 🧭 **Command surface: native vs compat, and which verb to use: [docs/CLI-SURFACE.md](docs/CLI-SURFACE.md)**
- 🛡️ **Policy DSL (`omc.policy`) — complete reference: [docs/POLICY.md](docs/POLICY.md)**
- 🪱 **Supply-chain worm defense + CI/dev recipes: [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md)**
- 🤖 Agent skill: [SKILL.md](SKILL.md)
- 🏗️ Architecture: [docs/oss-microcode-runtime.md](docs/oss-microcode-runtime.md)
- 📦 Releasing: [docs/RELEASING.md](docs/RELEASING.md)

> Private repo: `brew install` and release downloads need `export HOMEBREW_GITHUB_API_TOKEN=…` (or `gh release download`).
