---
name: omc-policy
description: >-
  Use when writing or editing an `omc.policy` file, configuring OMC capability /
  data-flow / package-age policy in `omc.toml` or `~/.omc/omc.toml`, or running
  the `omc` CLI to add/install/run packages under its deny-by-default model.
  OMC is a drop-in npm/PyPI replacement that compiles packages to verified,
  capability-typed bytecode and never runs install scripts.
---

# Authoring OMC policy (`omc.policy`) and using `omc`

OMC is **deny-by-default**. A dependency gets **no** host access (env vars,
files, network, processes, dynamic eval) unless a policy grants it, and a
sensitive data flow (e.g. an env secret reaching the network) is **rejected**
unless explicitly allowed. Reading sensitive files (`~/.ssh`, `.env`, keys,
`.npmrc`/`.pypirc` tokens, cloud creds) is denied **even under a wildcard
`read "*"` / `--allow-all-host`** unless `allow-sensitive` is set. Install
scripts never run.

Grant the **least** a package needs. When unsure, grant nothing and let it fail
closed — then add the specific capability the error names.

## Core workflow

```bash
omc --project-dir DIR init --name myapp          # new project (omc.toml, omc.lock, .omc/)
omc --project-dir DIR add --npm left-pad@1.3.0   # resolve + verify (no scripts run)
omc --project-dir DIR add --pypi requests==2.32.3 --allow net "*"
omc --project-dir DIR install                    # from package.json / requirements.txt / omc.toml
omc --project-dir DIR install --locked           # in-place locked install (reuse + prune node_modules)
omc --project-dir DIR ci                          # clean install: wipe OMC-managed trees, install strictly from omc.lock
omc --project-dir DIR list                        # inventory of locked packages (read-only; always exits 0)
omc --project-dir DIR audit                       # CI gate: list locked packages, exit non-zero (2) if any blocked
omc --project-dir DIR policy validate             # parse omc.policy: OK or a located error
omc --project-dir DIR policy check stripe@13.1.0 --npm   # effective compiled policy for a package
omc --project-dir DIR policy list                 # global accepted package grants
```

One-shot grants on `add`/`install`: `--allow`, `--allow-flow`,
`--allow-all-host`, `--allow-sensitive`. Persistent policy belongs in
`omc.policy` / `omc.toml`.

## The `omc.policy` DSL (per-package policy)

Place `omc.policy` next to `omc.toml`. It scopes grants to individual packages: a
`default` baseline plus `package` blocks. **No `omc.policy` ⇒ unchanged
behaviour.** Malformed input is a hard error with `line:column` — never silently
permissive. Comments use `#`; strings are double-quoted.

```
# omc.policy
default {
  allow time, random            # harmless baseline for every package
  min-age "14d"                 # reject any version published < 14 days ago
}

package "is-odd" { pure }                       # zero host capabilities

npm package "stripe" >=12.0.0 {                 # ecosystem + version-scoped block
  allow env "STRIPE_API_KEY"
  allow net "api.stripe.com"
  flow env "STRIPE_API_KEY" -> net "api.stripe.com"   # permit secret -> this host
}

package "trusted-internal" { min-age "0" }      # exempt from the age floor

npm package "@acme/*" {                          # name globs (`*`)
  allow net "registry.acme.com"                  # only this host (grants are an allow-list)
}

package "no-clock" { deny time, random }         # deny removes a default/earlier grant
```

> Grants are an **allow-list** — you can't express "any host except X". `deny`
> *removes* a grant the `default` added; a specific `deny net "X"` also strips a
> broad `net "*"` (so `allow net "*"` then `deny net "X"` leaves **no** network).

### Statements (inside a block)

| Statement | Effect |
|---|---|
| `allow <cap>, <cap>, …` | Grant capabilities. |
| `deny <cap>, …` | Remove matching grants (layer over `default`). `deny net "*"` removes all hosts; `deny net "h"` removes that host and a broad `net "*"`. |
| `pure` | Reset capabilities to none for this package (overrides `default` grants). |
| `allow-sensitive` | Lift the sensitive-file read guard for this package. |
| `flow <src> -> <sink>` | Permit a tainted source→sink data flow (else rejected). |
| `min-age "<dur>"` | Require a min release age (supply-chain freshness). |

### Capabilities (`allow` / `deny`)

| DSL | Grants |
|---|---|
| `env "NAME"` | read env var (`"*"` = any) |
| `read "PATH"` | read a file (sensitive paths still denied unless `allow-sensitive`) |
| `write "PATH"` | write a file |
| `net "HOST"` / `http "HOST"` | HTTP(S) to host (`"*"` = any) |
| `dns "HOST"` | DNS lookup |
| `spawn "CMD"` / `exec "CMD"` | spawn a process |
| `eval` | dynamic eval / `new Function` (no target) |
| `time` | read the clock (no target) |
| `random` | CSPRNG bytes (no target) |

### Flows (`flow src -> sink`)

- **src:** `env "NAME"`, `read "PATH"` (or `file "PATH"`), `secret "NAME"`, `any`
- **sink:** `net "HOST"` (or `http`), `write "PATH"`, `spawn "CMD"` (or `exec`), `eval`

### Block headers

- `default { … }` — applies to all packages (at most one).
- `[npm|pypi] package "<glob>" [<version-constraint>] { … }`
- Globs: `*` wildcard (`is-*`, `@acme/*`).
- Version constraint scopes the block's **capabilities** (not `min-age`):
  `==`, `>=`, `>`, `<=`, `<`, `^` (caret), `~` (tilde). e.g. `>=12.0.0`, `^1.2.0`.

### Package-age checks (`min-age`)

A **14-day** `min-age` floor is built in and **on by default** — even with no
`omc.policy`/`omc.toml`, a version published less than 14 days ago is rejected.
Require a version to be at least N old. Durations: `Nd` days, `Nh` hours,
`Nm` minutes, `Nw` weeks, `Ns` seconds, bare `N` = days, `0` = disable the
requirement (at any layer). **`min-age` is keyed by package NAME** — a version constraint on the block does
NOT scope it; put `min-age` in `default` or name-only blocks. A package block can
tighten (`min-age "30d"`) or exempt (`min-age "0"`) vs. the `default`.

## `omc.toml` and global `~/.omc/omc.toml`

Non-DSL knobs live in `[policy]`:

```toml
[policy]
allow      = ["http:api.example.com", "env:API_TOKEN"]     # flat grants (capability strings)
allow-flow = ["env:API_TOKEN -> network:api.example.com"]
min-release-age = "14d"                                    # project-wide age floor (built-in default; "0" disables)
```

A **global** policy at `~/.omc/omc.toml` (override dir via `$OMC_HOME`) applies to
every project: its `allow`/`allow-flow` are unioned **under** the project's, and
its `min-release-age` overrides the built-in 14-day default for every project (a
project's own `min-release-age` overrides it in turn). Effective min-age
precedence (most specific wins): `omc.policy` `min-age` → project `omc.toml` →
global `~/.omc/omc.toml` → built-in 14-day default.

## Rules for an agent

1. **Deny-by-default, least privilege.** Grant only the exact capability a
   package needs; prefer specific targets (`net "api.x.com"`) over `"*"`.
2. **Secrets to sinks need a `flow`.** Granting `env` + `net` is not enough to
   send the env value to the network — add `flow env "X" -> net "host"`.
3. **Never blanket `allow-sensitive`** or `--allow-all-host` to make something
   work; scope to the one package, and grant the exact `read "PATH"` instead when
   possible.
4. **Validate after editing:** run `omc policy validate`, then
   `omc policy check <pkg>` to confirm the effective policy.
5. **A parse error is intentional** — fix the policy; OMC will not run on a
   malformed one.

Full reference: [docs/POLICY.md](docs/POLICY.md). Project quickstart:
[docs/REFERENCE.md](docs/REFERENCE.md).
