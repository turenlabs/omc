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

**Every field, statement, capability, flow, version operator, and the
project/global config — see [docs/POLICY.md](docs/POLICY.md).**

---

- 📖 **[Quickstart & full reference →](docs/REFERENCE.md)**
- 🛡️ **Policy DSL (`omc.policy`) — complete reference: [docs/POLICY.md](docs/POLICY.md)**
- 🤖 Agent skill: [SKILL.md](SKILL.md)
- 🏗️ Architecture: [docs/oss-microcode-runtime.md](docs/oss-microcode-runtime.md)
- 📦 Releasing: [docs/RELEASING.md](docs/RELEASING.md)

> Private repo: `brew install` and release downloads need `export HOMEBREW_GITHUB_API_TOKEN=…` (or `gh release download`).
