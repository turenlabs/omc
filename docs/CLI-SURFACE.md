# OMC CLI Surface

OMC is **deny-by-default**: it resolves a package, profiles its source into
capability-typed bytecode, and accepts or blocks it *without ever running the
package's code*. The command surface has a few overlapping pairs — native vs
compat, install vs ci, list vs audit, run vs script — that are easy to confuse.
This file is the map.

All help strings below are taken verbatim from `omc --help` / `omc <cmd>
--help`. Exit codes follow the engine convention: **`0` = accepted, `2` =
blocked** (and `omc audit` reuses `2` as its CI-gate failure code).

---

## Native vs compat

OMC exposes the same deny-by-default engine through two surfaces.

**Native commands** (`omc add`, `omc install`, `omc remove`) are the OMC-managed
surface. They read and write `omc.toml` / `omc.lock`, install into the
OMC-managed trees (`node_modules`, `.omc/python/...`), and enforce the verdict
directly.

| Native | Help string |
|---|---|
| `omc add <spec…>` | Resolve, verify, lock, and install a package plus dependencies |
| `omc install` | Resolve omc.toml dependencies and install locked packages |
| `omc remove <spec…>` | Remove an OMC-managed dependency and reinstall remaining manifest inputs |

**Compatibility shims** (`omc npm`, `omc pip`, `omc twine`) are drop-in
ecosystem CLIs routed through the *same* engine. They accept the familiar
npm/pip/twine subcommands and flags but apply OMC's verdict instead of the
upstream tool's behavior.

| Compat | Help string |
|---|---|
| `omc npm …` | Run common npm-compatible commands through OMC |
| `omc pip …` | Run common pip-compatible commands through OMC |
| `omc twine …` | Run common Twine-compatible PyPI publish commands through OMC |

`omc add` **is** the native install; `omc npm install` and `omc pip install` are
the compat equivalents. Same engine, same deny-by-default verdict — only the
command surface differs. Use native when you are committing to the OMC project
model; use the compat shims when slotting OMC into an existing npm/pip workflow.

Specs are accepted in prefixed form (`npm:left-pad@1.3.0`, `pypi:idna==3.7`) or
unprefixed with `--npm` / `--pypi` to pick the ecosystem.

---

## Installing

Three commands install from the project, and they differ in whether they
*resolve* the registry and whether they *wipe* the existing install tree.

| Command | Help string |
|---|---|
| `omc install` | Resolve omc.toml dependencies and install locked packages |
| `omc install --locked` | Install in place from omc.lock without registry resolution (reuse and prune node_modules; use `omc ci` for a clean wipe) |
| `omc ci` | Clean install for CI: wipe the OMC-managed install trees, then install strictly from omc.lock |

| | Resolves registry? | Wipes `node_modules`? | For CI? |
|---|---|---|---|
| `omc install` | yes | no | no |
| `omc install --locked` | no (from lock) | no — reuses and prunes in place | optional |
| `omc ci` | no (from lock) | yes — wipes the OMC-managed trees first | yes |

- **`omc install`** — the everyday path: resolve `omc.toml` / `package.json` /
  `requirements.txt`, lock, and install.
- **`omc install --locked`** — an in-place locked install. It reuses an existing
  `node_modules`, prunes anything not in `omc.lock`, and does no registry
  resolution. Fast and non-destructive.
- **`omc ci`** — the from-scratch CI variant. It first wipes the OMC-managed
  install trees (`node_modules`, `.omc/python/{site-packages,bin,sdists,vcs}`,
  local-paths) and then installs strictly from `omc.lock`. Use this when you
  want a guaranteed clean tree on every run.

So `omc ci` is from-scratch clean and `omc install --locked` is in-place: they
are **not** identical.

---

## Inspecting before install

Inspect a package without writing anything to the project. Resolution and
profiling happen in a throwaway temp dir — no `omc.lock`, manifest,
`node_modules`, or `site-packages` is touched.

| Command | Help string |
|---|---|
| `omc inspect <spec…>` | Resolve and show a package's capabilities without installing (text report, or `--format png` graph) |
| `omc inspect <spec…> --format png` | (same command; `--format` selects output) Output format: text (default, full capability report) or png (a dependency-graph image) |
| `omc scan` | Read-only scan of an existing project: capability-verdict every package its manifests and lockfiles declare (exit 2 if any would be blocked) |
| `omc diff <old> <new>` | Compare two package versions: capability, dependency, and verdict changes between old and new (read-only) |
| `omc policy check <pkg>[@ver]` | Show the effective compiled policy for a package, e.g. `omc policy check stripe@13.1.0` |

- **`omc inspect <spec>`** (default `--format text`) — the full per-file
  capability report: every finding, its evidence, and the verdict. This is the
  read-only equivalent of `omc add -v`. Use it to see exactly what a package and
  its transitive deps can do before trusting them.
- **`omc inspect <spec> --format png [--output FILE]`** — render the dependency
  tree as a PNG, nodes colored by risk (default output `omc-graph.png`). Use
  this for a quick visual of the dependency graph's risk shape.
- **`omc scan`** — the project-level sibling of inspect. It takes no specs:
  it reads the manifests and lockfiles already in the project directory
  (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml,
  requirements.txt, Pipfile.lock, uv.lock, poetry.lock, pyproject.toml, …),
  resolves and profiles every declared package in a throwaway temp dir, and
  reports the verdicts. No omc.toml is required and nothing is written to the
  project. Unlike inspect, scan IS a gate: it exits `2` when any scanned
  package would be blocked, so it can sit in CI on a project that does not use
  OMC to install. `--json` for machine-readable output, `--omit-dev` to skip
  development dependencies. Python `git+…` requirements are not resolved; the
  report says how many were skipped.
- **`omc diff <old> <new>`** — resolve and profile two package versions (each
  in its own throwaway dir) and report the delta: capabilities added/removed
  by (package, kind, target) with evidence files, dependencies
  added/removed/version-changed, and the verdict on each side. This is the
  upgrade escalation check: "can the new version do anything the old one
  couldn't?" Informational like inspect (always exit 0); `--json` output has
  an `escalation` boolean to gate dependency-bump PRs on.
- **`omc policy check <pkg>`** — show the *effective compiled policy* for a
  package: the grants that actually apply after merging defaults, `omc.policy`,
  and the global store. Use this to answer "what is this package allowed to do
  under my policy?" rather than "what does this package want to do?".

`inspect` and `scan` accept the same `--allow` / `--allow-flow` /
`--allow-all-host` grants so you can preview how a grant would change the
verdict(s).

Inspect-vs-scan-vs-diff: `inspect` takes registry **specs**, `scan` takes the
**project directory** (via the global `--project-dir`, default `.`), and
`diff` takes **two specs** to compare. All three are read-only and resolve
into throwaway temp dirs.

> `omc graph <spec>` is a hidden, deprecated alias for `omc inspect <spec>
> --format png`. Prefer `omc inspect --format png`.

---

## Inventory vs gate

Both list locked packages, but they serve opposite purposes.

| Command | Help string |
|---|---|
| `omc list` | Show the inventory of locked packages (read-only; always exits 0) |
| `omc audit` | CI gate: list locked packages and exit non-zero (2) if any are blocked |

- **`omc list`** — a read-only inventory of what is locked. It never fails:
  **always exits 0**. Use it to see what is installed.
- **`omc audit`** — the CI gate. It lists the same locked packages but **exits
  non-zero (code 2) if any package is blocked**. Use it in CI to fail the build
  on a blocked dependency.

Both accept `--json` for machine-readable output. If you need a pass/fail
signal, use `audit`; if you just want the inventory, use `list`.

---

## Running project code

OMC enforces at install time. At runtime it simply puts your real interpreter
and the project's OMC-installed bins/imports on `PATH`
(`node_modules` / `.omc/python/site-packages`).

| Command | Help string |
|---|---|
| `omc run <cmd> [args…]` | Run a command with OMC npm/Python bins and imports on PATH |
| `omc script <name> [args…]` | Run a package.json or Pipfile script with OMC npm/Python bins and imports |
| `omc node [args…]` | Run node with this project's OMC-installed node_modules |
| `omc python [args…]` | Run python3 with this project's OMC-installed site-packages |

- **`omc run <cmd>`** — run an *arbitrary* command (any executable) with the OMC
  bins and import paths in place. The command is whatever you type.
- **`omc script <name>`** — run a *named* script defined in `package.json`
  (`scripts`) or a `Pipfile`. The name is looked up; you do not spell out the
  command.
- **`omc node` / `omc python`** — drop straight into the interpreter with the
  project's OMC import paths configured.

Run-vs-script: `run` takes the literal command line; `script` takes the *name*
of a script your project already defines.

The compat shims cover the npm equivalents:

- `omc npm run <name>` — run a named `package.json` script (compat form of
  `omc script`).
- `omc npm exec <cmd>` — execute a command/binary through the npm-compatible
  surface (compat form of `omc run`).

---

## Policy

Grants can be persisted at two scopes — per-project (`omc.toml`) or globally
(`~/.omc/policy.d/`) — and inspected with the read-only subcommands.

| Command | Help string |
|---|---|
| `omc policy allow <grant…> [--flow <flow>]` | Persist project policy grants in omc.toml |
| `omc policy grant <spec> --allow <grant>` | Grant a package globally: write a version-pinned grant to `~/.omc/policy.d/` |
| `omc policy check <pkg>[@ver]` | Show the effective compiled policy for a package |
| `omc policy list [scope]` | List accepted policy grants; defaults to the global trust store |
| `omc policy validate` | Parse omc.policy and report OK, or the parse error with its location |

- **`omc policy allow`** — persist a grant into `omc.toml`'s flat `[policy]`
  allow-list for the *whole project*.
- **`omc policy grant <spec>`** — write a **version-pinned global** grant as a
  drop-in under `~/.omc/policy.d/`. It applies in every project but only to that
  exact package+version. Example:
  `omc policy grant pypi:requests@2.32.5 --allow dynamic.eval --allow-flow 'env:*->network:*'`.
  Delete the file to revoke.
- **`omc policy check`** — show the effective compiled policy for a package (see
  "Inspecting before install").
- **`omc policy list`** — list accepted grants; defaults to the global store,
  which `omc policy list` output refers to as the **trust store**.
- **`omc policy validate`** — parse `omc.policy` and report OK, or a located
  parse error.

> `omc policy trust` is a hidden alias for `omc policy grant`. Prefer
> `omc policy grant`. Note this is unrelated to the npm-compat `omc npm trust`
> (registry trusted-publishing), which is a separate command and surface.

---

## Hidden and deprecated aliases

A couple of commands are kept only for back-compat and do not appear in
`--help`:

- **`omc graph`** — hidden, deprecated alias for `omc inspect --format png`.
- **`omc policy trust`** — hidden alias for `omc policy grant`.

Both still work, but new usage should prefer the current commands above.
