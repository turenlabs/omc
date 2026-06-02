//! `omc agent` — emit a self-contained Markdown (or JSON-wrapped) "skill"
//! document that an AI agent can read to drive omc correctly.
//!
//! The guide is a compile-time constant kept in lockstep with the real
//! `Command` set and flags in [`crate::args`]; it never invents flags. Tests in
//! `crate::tests` assert the presence of the load-bearing anchors so drift is
//! caught at `cargo test` time.

use std::process::ExitCode;

/// The full agent guide, in Markdown. Keep this accurate to `args.rs`.
const AGENT_SKILL_MARKDOWN: &str = r#"# omc — AI agent usage guide

## What omc is

`omc` is a **deny-by-default** drop-in replacement for `npm` and `pip`. It does
**not** execute package code to install it. Instead it resolves a package,
compiles its JavaScript/Python source to a small **capability-typed bytecode**,
and computes a verdict by *reading* the code. Anything dangerous is **denied
unless you explicitly grant it**.

Because omc **never runs install/postinstall scripts** (npm lifecycle hooks,
Python `.pth` / `sitecustomize.py`) and never imports a package to install it,
install-time-code-execution worms such as **Shai-Hulud** cannot run at all: a
lifecycle hook surfaces as a blocked `proc.spawn`, obfuscation as
`dynamic_eval`, and any secret -> network data flow is denied without a grant.

Mental model: **dependencies are behavior-typed artifacts, not trusted code.**
Enforcement happens at *install* time (resolution + source profiling + verdict),
not as a runtime sandbox around host-run code.

## Core workflow

```bash
omc init --name myapp                 # create omc.toml, omc.lock, .omc/
omc add --npm left-pad@1.3.0          # resolve + verify + lock + install one package
omc add --pypi idna==3.7              # PyPI; or use prefixes: omc add npm:left-pad@1.3.0
omc install                           # resolve omc.toml/package.json/requirements.txt and install locked
omc ci                                # install strictly from omc.lock, no registry resolution
omc list                              # list locked packages (--json)
omc audit                             # summarize locked packages; non-zero exit if any blocked (--json)
omc remove --npm left-pad             # drop a dependency and reinstall the rest
```

Spec forms accepted everywhere: prefixed (`npm:left-pad@1.3.0`,
`pypi:idna==3.7`) or unprefixed with `--npm` / `--pypi` to pick the ecosystem.

### Running installed code

omc enforces at install time; at runtime it just puts your real interpreter on
an isolated import path (`node_modules` / `.omc/python/site-packages`):

```bash
omc node -e "console.log(require('is-odd')(3))"   # node with project node_modules
omc python -c "import requests; print(requests)"  # python3 with project site-packages
omc run <cmd> [args...]                            # run any command with OMC bins/imports on PATH
omc script <name> [args...]                        # run a package.json / Pipfile script
```

### Compatibility shims

`omc npm ...`, `omc pip ...`, and `omc twine ...` accept common npm/pip/twine
subcommands and route them through omc's deny-by-default engine. The standalone
`node` / `npm` / `pip` / `python` drop-in binaries (opt-in on `PATH`) behave the
same way.

### Compiling local source

```bash
omc compile --npm ./my-pkg --name my-pkg --version 1.0.0   # profile local source to a signed artifact
omc exec-cell ./script.js --arg 3                          # lower JS/Py to microcode + run in the fueled VM
```

`omc exec-cell` is the experimental capability-gated *execution* path (runs
package logic inside the verified VM under the project policy), distinct from the
install-time-only enforcement of every other command.

## Reading output & verdicts

- A package is either **accepted** or **blocked**. Output is a terse per-package
  tree plus a one-line risk callout summarizing capability kinds.
- For the full per-file capability dump, pass `-v` / `--verbose` or set
  `OMC_VERBOSE=1`.
- **Exit codes: `0` = accepted, `2` = blocked.** `omc audit` also exits non-zero
  when any locked package is blocked. Script accordingly.
- When a package is blocked, the message prints the **exact grant** needed to
  unblock it — copy it verbatim.

## Capability kinds (plain language)

- `env_read` — reads environment variables.
- `fs_read` — reads files.
- `fs_write` — writes files.
- `http_request` — makes network requests.
- `proc_spawn` — spawns subprocesses.
- `dynamic_eval` — runs code built at runtime (eval / new Function / exec).

**Auto-accepted at install** (benign runtime capabilities): `env_read`,
`fs_read`, `http_request`, plus pure things like time/random.

**Deny-by-default** (must be granted): `proc_spawn`, `dynamic_eval`, `fs_write`,
reads of **sensitive files** (`~/.ssh`, `.env`, keys, tokens), and any
**secret -> sink data flow** (e.g. env var -> network). Sensitive-file reads stay
blocked **even under `--allow-all-host`**; grant them by exact path.

## Granting access

Most commands that resolve packages (`add`, `install`, `ci`, `remove`,
`compile`, `exec-cell`) accept:

- `--allow <grant>` — grant a capability. Examples:
  - `--allow http:api.example.com`  (host)
  - `--allow env:API_TOKEN`         (named env var)
  - `--allow fs-read:*`             (wildcard file read)
  - `--allow proc:*`                (process spawn)
- `--allow-flow <flow>` — grant a data flow, e.g.
  `--allow-flow env:API_TOKEN->network:api.example.com`.
- `--allow-all-host` — grant all host capabilities for compatibility testing
  (still does NOT unblock sensitive-file reads).

### Persisting grants

- `omc allow <grant> [--flow <flow>]` — persist a grant into `omc.toml`'s flat
  `[policy]` allow-list for the whole project.
- **`omc.policy`** (per-package DSL) — drop a file next to `omc.toml` to scope
  grants to *individual* packages: a `default` baseline plus `package` blocks
  that `allow`/`deny` capabilities, declare `flow`s, mark a package `pure`, or
  set `min-age`. Deny-by-default: a package with no matching block gets no
  grants. Inspect it:
  - `omc policy validate` — parse `omc.policy`; OK or a located error.
  - `omc policy check <pkg>[@version]` — show the effective compiled policy.
- **Trust store** — `omc trust <spec> --allow <grant> [--allow-flow <flow>]`
  writes a **version-pinned** drop-in to `~/.omc/policy.d/` that applies in every
  project but only to that exact package+version. Example:
  `omc trust pypi:requests@2.32.5 --allow dynamic.eval --allow-flow 'env:*->network:*'`.
  Delete the file to revoke.

### Supply-chain freshness

Set a minimum release age so a just-published (possibly malicious) version is
refused until it has been live long enough: `min-release-age = "14d"` in
`omc.toml` `[policy]` or the global `~/.omc/omc.toml`, or `min-age "14d"` per
package in `omc.policy` (`14d` / `12h` / `2w` / `7` days / `0` = off).

## Knobs an agent may set

- `OMC_VERBOSE=1` — full per-file capability dump (same as `-v`).
- `OMC_HOME` — override the omc home dir (default `~/.omc`); relocates the global
  `omc.toml`, the `policy.d/` trust store, and caches.
- `OMC_META_TTL_SECS` — registry metadata cache TTL in seconds.
- `NO_COLOR` — disable colored output.

## Quick recipe

```bash
omc init --name app
omc add --npm some-pkg@1.2.3            # if blocked, exit code 2 + the exact --allow line
omc add --npm some-pkg@1.2.3 --allow http:registry.npmjs.org   # re-run with the grant
omc audit --json                        # gate CI: non-zero if anything is blocked
```
"#;

/// Render the agent guide. With `json = true`, wrap the Markdown as a single
/// JSON object so machine callers can consume it without parsing Markdown.
pub(crate) fn agent_skill_document(json: bool) -> String {
    if json {
        let escaped =
            serde_json::to_string(AGENT_SKILL_MARKDOWN).unwrap_or_else(|_| "\"\"".to_owned());
        format!("{{\"format\":\"markdown\",\"skill\":{escaped}}}")
    } else {
        AGENT_SKILL_MARKDOWN.to_owned()
    }
}

/// Print the agent guide to stdout. Always succeeds (exit code 0).
pub(crate) fn print_agent_skill(json: bool) -> ExitCode {
    println!("{}", agent_skill_document(json));
    ExitCode::SUCCESS
}
