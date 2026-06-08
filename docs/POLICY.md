# OMC Policy DSL (`omc.policy`)

OMC is **deny-by-default**: a dependency gets no host access (env, files, network,
processes, dynamic eval) unless a policy grants it, and a sensitive data flow
(e.g. an env secret reaching the network) is rejected unless explicitly allowed.

The `omc.policy` file is a small declarative language that scopes those grants to
**individual packages** — far more expressive than the single flat allow-list in
`omc.toml [policy]`. This is the complete reference.

- File: `omc.policy`, placed next to `omc.toml` in the project root.
- Optional: with no `omc.policy`, behaviour is exactly the historical flat
  `[policy]` allow-list (full back-compat).
- **Fail-closed:** a malformed file, unknown keyword, unknown capability, or
  stray token is a hard error with a `line:column`. The parser never yields a
  silently-empty or silently-permissive policy.
- Validate / inspect: `omc policy validate`, `omc policy check <pkg>[@ver]`,
  and `omc policy list` for the global trust store.

---

## Grammar

```text
document          := item*
item              := default_block | package_block
default_block     := "default" "{" stmt* "}"            # at most one
package_block     := [ecosystem] "package" STRING [version_constraint] "{" stmt* "}"
ecosystem         := "npm" | "pypi"
version_constraint:= op (STRING | bareversion)          # e.g.  >=12.0.0   or   == "1.2.3"
op                := "==" | ">=" | ">" | "<=" | "<" | "^" | "~"
stmt              := "pure"
                   | "allow-sensitive"
                   | ("allow" | "deny") cap ("," cap)*
                   | "flow" flow_src "->" flow_sink
                   | "min-age" STRING
cap               := ("env"|"read"|"write"|"net"|"http"|"dns"|"spawn"|"exec") STRING
                   | "eval" | "time" | "random"
flow_src          := ("env"|"file"|"read"|"secret") STRING | "any"
flow_sink         := ("net"|"http") STRING | "write" STRING | ("spawn"|"exec") STRING | "eval"
```

- **Comments** start with `#` and run to end of line.
- **Strings** are double-quoted (`"…"`) and support `\"` / `\\` escapes.
- Whitespace and newlines are insignificant.

---

## Blocks

| Block | Applies to |
|---|---|
| `default { … }` | Every package (the baseline). At most one per file. |
| `package "<glob>" { … }` | Packages whose name matches the glob, any ecosystem. |
| `npm package "<glob>" { … }` | npm packages matching the glob. |
| `pypi package "<glob>" { … }` | PyPI packages matching the glob. |

**Name globs** — `*` matches any (possibly empty) run of characters; multiple
`*` are allowed; literal characters match exactly. Examples: `"is-odd"`,
`"is-*"`, `"@acme/*"`, `"@acme/*-plugin"`.

**Version constraint** (optional, scopes the block's **capability** rules to
matching versions — *not* `min-age`, which is name-level):

| Operator | Meaning | Example |
|---|---|---|
| `==` | exact (numeric core; `12` == `12.0.0`) | `== "1.2.3"` |
| `>=` `>` `<=` `<` | numeric comparison | `>=12.0.0` |
| `^` | caret: locks the left-most non-zero component (`^1.2.3` ⇒ `>=1.2.3,<2.0.0`; `^0.2.3` ⇒ `<0.3.0`) | `^1.2.0` |
| `~` | tilde: locks the minor when given (`~1.2.3` ⇒ `<1.3.0`), else the major | `~1.2` |

Versions compare on their leading dotted-numeric core; a `v` prefix is tolerated
and any `-prerelease`/`+build` suffix is ignored for ordering. A non-numeric
version is incomparable, so only a verbatim `==` can match it.

---

## Statements

### Capabilities — `allow` / `deny`

`allow cap, cap, …` grants; `deny cap, cap, …` removes matching grants (for
layering over the `default`). Each capability:

| DSL | Grants | Notes |
|---|---|---|
| `env "NAME"` | read env var `NAME` | `env "*"` = any var |
| `read "PATH"` | read file `PATH` | sensitive paths (`~/.ssh`, `.env`, keys, tokens) stay denied even under `read "*"` unless `allow-sensitive` |
| `write "PATH"` | write file `PATH` | |
| `net "HOST"` / `http "HOST"` | HTTP(S) request to `HOST` | identical; `net "*"` = any host |
| `dns "HOST"` | DNS lookup of `HOST` | |
| `spawn "CMD"` / `exec "CMD"` | spawn process `CMD` | identical |
| `eval` | dynamic eval / `new Function` | no target |
| `time` | read the clock | no target |
| `random` | read CSPRNG bytes | no target |

The wildcard target `"*"` matches anything of that kind. `deny net "*"` removes
all host grants for the package; `deny net "api.x"` removes that host **and** a
broad `net "*"` (so the denied host can't leak back in).

### `pure`

Reset the accumulated capabilities to **none** for this package (it overrides any
`default` grants). Flow rules and `allow-sensitive` are independent and untouched.

### `allow-sensitive`

Lift the sensitive-file read guard for this package, so `read "*"` /
`--allow-all-host` may read `~/.ssh`, `.env`, keys, and tokens. Off by default.

### `flow src -> sink`

Permit a tainted data flow. Without a matching `flow`, OMC rejects a secret
reaching a sink (e.g. `env "TOKEN"` value sent to the network).

| `flow_src` | Matches a value labelled |
|---|---|
| `env "NAME"` | from env var `NAME` |
| `read "PATH"` / `file "PATH"` | from file `PATH` |
| `secret "NAME"` | a tracked secret `NAME` |
| `any` | any source |

| `flow_sink` | The value reaching |
|---|---|
| `net "HOST"` / `http "HOST"` | a network host |
| `write "PATH"` | a file write |
| `spawn "CMD"` / `exec "CMD"` | a spawned process |
| `eval` | dynamic eval |

Example: `flow env "STRIPE_API_KEY" -> net "api.stripe.com"`.

### `min-age "<duration>"` — package-age check

Require a package version to have been **published at least this long ago** to be
installed (a supply-chain freshness gate against just-published malware).
Enforced at version resolution for npm and PyPI; too-new versions are filtered
and the newest old-enough version is chosen.

This gate is **on by default**: with no `min-age` and no `min-release-age`
configured anywhere, a built-in **14-day floor** applies out of the box. Set an
explicit `"0"` at any scope to relax or disable it (see precedence below).

| Duration | Meaning |
|---|---|
| `"14d"` | 14 days |
| `"12h"` | 12 hours |
| `"30m"` | 30 minutes |
| `"2w"` | 2 weeks |
| `"45s"` | 45 seconds |
| `"7"` | bare number = days |
| `"0"` | no requirement (explicit exempt — disables the floor for this scope) |

`min-age` is evaluated by package **name** — a version constraint on the block
does *not* scope it, so put `min-age` in `default` or name-only `package` blocks.
A package block can tighten (`min-age "30d"`) or exempt (`min-age "0"`) relative
to the `default`. A malformed duration is a hard parse error.

---

## Semantics

For a concrete `(ecosystem, name, version)` the effective policy is built by:

1. apply the `default` block, then
2. apply every matching `package` block **in source order** (ecosystem
   unqualified-or-equal **and** name-glob matches **and** version constraint, if
   any, satisfied).

`pure` resets caps; `allow` adds; `deny` removes; `flow` appends; `allow-sensitive`
lifts the guard. A package with **no** matching block (and no `default` grant)
gets nothing — deny-by-default.

The `omc.toml [policy]` grants remain a baseline that the DSL layers on top of.

---

## Project & global configuration (`omc.toml`, `~/.omc/omc.toml`)

Non-DSL knobs live in `omc.toml`'s `[policy]` table (and the same table in the
global file):

```toml
[policy]
allow      = ["http:api.example.com", "env:API_TOKEN"]   # flat capability grants
allow-flow = ["env:API_TOKEN -> network:api.example.com"]
min-release-age = "14d"                                  # project-wide age floor
```

**Global policy** `~/.omc/omc.toml` (override the directory with `$OMC_HOME`;
defaults to `$HOME/.omc`) applies to **every** project:

- `allow` / `allow-flow` are **unioned under** the project's grants.
- `min-release-age` is the **lowest-precedence floor**; a project's `omc.toml`
  value, or an `omc.policy` `min-age`, overrides it.
- Absent ⇒ the built-in **14-day** floor still applies (the gate is on by
  default); malformed ⇒ hard error.

**Effective min-age precedence** (most specific wins): `omc.policy` `min-age`
→ project `omc.toml` `min-release-age` → global `~/.omc/omc.toml`
`min-release-age` → **built-in 14-day default**. The gate is therefore **on by
default** (14 days) even with zero config; an explicit `"0"` at any layer relaxes
or disables it for that scope. It combines with an explicit `--before` /
`--uploaded-prior-to` by taking the more restrictive cutoff.

---

## Commands

```bash
omc policy allow <grant> [--flow <flow>]          # persist project-wide grants in omc.toml
omc policy grant <spec> --allow <grant> [...]     # write version-pinned global trust
omc policy validate                              # parse omc.policy; OK or a located error
omc policy check <pkg>[@<ver>] [--npm|--pypi]    # print the effective compiled policy
omc policy list [global]                         # list global accepted package grants
```

`omc policy check` defaults to npm and version `0.0.0` when omitted; scoped npm
names keep their `@` (`omc policy check @acme/widget@2.0.0`). One-shot CLI grants
on `omc add`/`install` layer on top: `--allow`, `--allow-flow`, `--allow-all-host`,
`--allow-sensitive`. `omc policy list` defaults to `global`, which reads the
drop-in trust store at `$OMC_HOME/policy.d/` (default `~/.omc/policy.d/`).

> `omc policy grant` was previously named `omc policy trust`; `omc policy trust`
> remains a hidden alias for back-compat.

---

## Worked example

```
# omc.policy
default {
  allow time, random            # harmless baseline for every package
  min-age "14d"                 # nothing younger than 14 days
}

package "trusted-internal" { min-age "0" }     # exempt our own package from the age floor

package "no-clock" { deny time, random }        # opt this package out of the default grants

npm package "stripe" >=12.0.0 {
  allow env "STRIPE_API_KEY"
  allow net "api.stripe.com"
  flow env "STRIPE_API_KEY" -> net "api.stripe.com"
}

npm package "@acme/*" {
  allow net "registry.acme.com"  # only this host (grants are an allow-list)
}

pypi package "requests" {
  allow net "*"
}
```

> Grants are an **allow-list**: you cannot express "any host *except* X". `deny`
> *removes* a grant the `default` (or an earlier `allow`) added — and a specific
> `deny net "X"` also strips a broad `net "*"` so X can't leak back in (so
> `allow net "*"` then `deny net "X"` leaves **no** network grant, not "all but X").
