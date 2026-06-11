# OMC

**A drop-in `npm`/`pip` that never runs install scripts and won't let packages touch your secrets.**

![OMC in action: npm and pip packages install with no host access and no install scripts; then a risky one is inspected and blocked with the credential-exfiltration reason before it ever runs](docs/demo.gif)

Packages don't execute as JavaScript or Python when you install them. OMC resolves them, compiles their code to a small **verified bytecode**, and denies anything dangerous **by default**: reading env vars, files, the network, spawning processes. Reading sensitive files (`~/.ssh`, `.env`, keys, tokens) stays blocked *even with* `--allow-all-host`. Access is granted explicitly, per package, and recorded.

```bash
brew install turenlabs/tap/omc
# Recent Homebrew gates third-party taps. If you hit "Refusing to load formula
# … from untrusted tap", run `brew trust turenlabs/tap` and re-run the install.
```

## From zero to a running app

Here are two full walkthroughs, one for npm and one for Python. Each one sets up
a project, installs its packages with OMC, then runs the app with your normal
tools. Every command below is real and was tested.

### React + Vite (npm)

```bash
omc npm create vite@latest myapp -- --template react   # scaffold (runs under OMC, no install scripts)
cd myapp

omc install                    # stops on React: it uses eval, which OMC denies by default.
                               # it prints the exact grant so you can allow it on purpose
omc install --allow-all-host   # review, then allow and record. installs 136 packages (13 bins)

npm run dev                    # your normal Vite dev server, at http://localhost:5173
```

`npm run dev` uses the real `npm` and `node`. They run against the `node_modules`
folder OMC built, which is a normal folder, so you don't need anything special.
One rule: don't run `npm install` again. If you do, the real npm rebuilds the
folder and runs every install script that OMC skipped.

### FastAPI + Uvicorn (Python)

```bash
omc init --name myapi
omc add --pypi fastapi uvicorn --allow-all-host   # a web server uses the network, so allow and record

cat > main.py <<'EOF'
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def root():
    return {"ok": True}
EOF

omc python -m uvicorn main:app --port 8000        # serves http://localhost:8000 and returns {"ok":true}
```

OMC puts Python packages in `./.omc/python/site-packages`, which is not the normal
place. So run your app with `omc python` (or turn on the `python` shim). That is
the one difference from npm. With npm, plain `npm run dev` finds `./node_modules`
on its own.

A package that wants host access is **blocked** until you allow it:

```bash
omc add --npm esbuild@0.19.12                       # ✗ blocked (postinstall + network)
omc add --npm esbuild@0.19.12 --allow http:registry.npmjs.org   # ✓ allowed + recorded
```

That's the whole idea: **dependencies are behavior-typed artifacts, not trusted code.**

## Using what you install

Installed packages work normally. You just run them through OMC, which uses the
project's own isolated install tree (`node_modules` / `.omc/python/site-packages`):

```bash
omc add --pypi requests==2.32.3 --allow-all-host   # grant it (requests does network)
omc python -c "import requests; print(requests.get('https://example.com').status_code)"

omc add --npm is-odd@3.0.1
omc node -e "console.log(require('is-odd')(3))"
```

The `omc node` / `omc python` commands (and the drop-in `node`/`npm`/`pip`/`python`
shim names, opt-in on `PATH`) run your **real** interpreter with an isolated import
path. So `import requests` and `requests.get(...)` behave exactly like normal.
**OMC's enforcement happens at install time** (resolution, source profiling,
capability/flow/age verdicts, no install scripts), not as a runtime sandbox
around host-run code. Grants are recorded in `omc.lock`, so what each dependency
is allowed to do is auditable.

> Scope today: pure-Python wheels/sdists and npm packages. Packages that need a
> **native build** (C extensions like `numpy`/`cryptography` from source) aren't
> built yet. A sandboxed build chain with secure defaults is the natural next
> step.

## Try it on a project you already have

You don't have to migrate anything to see what OMC thinks of your dependencies.
`omc scan` reads the manifests and lockfiles your project already has
(`package.json`, `package-lock.json`, `requirements.txt`, `uv.lock`, `Pipfile.lock`,
and friends), profiles every package, and prints the verdicts. It never writes
to your project and never installs anything:

```bash
cd my-existing-app
omc scan            # ✓ or ✗ per package, with the evidence
omc scan --json     # machine-readable, for CI
```

The exit code is the same gate as the rest of OMC: `0` when everything is
accepted, `2` when something would be blocked. That means you can drop
`omc scan` straight into CI on a project that still installs with plain
npm or pip.

## Check an upgrade before you take it

Most supply-chain attacks ship inside an upgrade of a package you already
trust. `omc diff` profiles two versions and tells you what the new one can do
that the old one could not:

```bash
omc diff npm:lodash@4.17.20 npm:lodash@4.17.21
omc diff pypi:requests==2.31.0 pypi:requests==2.32.3 --json
```

The report covers new and removed capabilities (with the file that triggers
each one), dependency additions and removals, and verdict changes. The JSON
output has an `escalation` field you can gate a dependency-bump PR on.

## Docker and CI

OMC needs no runtime sandbox, no privileged mode, and no kernel features:
enforcement happens at install time as static analysis. In a container it is
one binary plus network access to the registries, so the deny-by-default gate
works in `docker build` exactly like it does locally. A blocked package exits
`2` and fails the build.

Releases ship Linux binaries for both `x86_64` and `aarch64` (so Docker on
Apple Silicon works without emulation), in two flavors: `gnu` for
glibc bases like `debian`/`ubuntu`, and fully static `musl` builds that run on
Alpine and even `FROM scratch`.

```dockerfile
FROM node:22-slim
# Pin the binary by checksum. Get the value from the release's SHA256SUMS file.
ADD --chmod=755 \
    --checksum=sha256:<sha256 of omc-x86_64-unknown-linux-gnu from SHA256SUMS> \
    https://github.com/turenlabs/omc/releases/download/v0.3.0/omc-x86_64-unknown-linux-gnu \
    /usr/local/bin/omc
WORKDIR /app
COPY package.json omc.toml omc.lock ./
# Clean install from omc.lock, then fail the build if anything is blocked.
RUN --mount=type=cache,target=/root/.omc omc ci && omc audit
COPY . .
CMD ["node", "server.js"]
```

Notes for container use:

- Containers are non-interactive, so OMC fails closed: there is no approval
  prompt. Commit the grants a package needs (`omc.toml` `[policy]` or
  `omc.policy`) before the build.
- The cache mount on `/root/.omc` (or set `$OMC_HOME`) keeps the
  content-addressed store warm across rebuilds without baking it into layers.
- The running container does not need omc: installs land in normal trees
  (`node_modules`, `.omc/python/site-packages`), so `node server.js` just
  works. Keep omc in the image only if you want `omc run` or the shims.
- For a project that does not use OMC to install yet, `omc scan` is the same
  gate without any migration.

## Per-package policy (`omc.policy`)

`omc.toml`'s `[policy]` block is one flat allow-list for the whole project. Drop an optional **`omc.policy`** file next to it to scope grants to *individual* packages. It has a `default` baseline plus `package` blocks that `allow`/`deny` capabilities, declare `flow`s, mark a package `pure`, or lift the sensitive-read guard:

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

To block just-published malware, OMC enforces a minimum **release age**. A version must have been published at least that long ago to install. This is **on out of the box**: with zero config there's a built-in **14-day floor**. Override it per-package in `omc.policy` (`min-age`), project-wide in `omc.toml`, or globally in `~/.omc/omc.toml`; set `0` at any layer to disable it for that scope.

```toml
[policy]
min-release-age = "30d"     # 14d / 12h / 2w / 7 (days) / 0 (off); built-in default is 14d
```

### Global policy (`~/.omc/omc.toml`)

OMC also reads a **global** user policy at `~/.omc/omc.toml` (override the dir with `$OMC_HOME`). Its `[policy]` grants are unioned under every project as a baseline, and its `min-release-age` overrides the built-in 14-day floor (and is itself overridable per project). Precedence, most specific first: `omc.policy` `min-age` (per package) → project `omc.toml` → global `~/.omc/omc.toml` → built-in **14-day default**. Use it to set an org-wide freshness floor or default grants once:

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
transitive dependencies, unlike a flat project-wide grant. Delete the file to
revoke. Hand-authored files in `~/.omc/policy.d/` work too. Run `omc policy
list` (or `omc policy list global`) to inspect those global accepts.

**Every field, statement, capability, flow, version operator, and the
project/global config: see [docs/POLICY.md](docs/POLICY.md).**

## Stopping supply-chain worms (Shai-Hulud)

Worms like Shai-Hulud spread through one mechanic: **install-time code execution**.
A `postinstall` hook (or `.pth` / `sitecustomize.py`) runs the moment you
install, harvests `~/.npmrc`/cloud creds/env, exfiltrates them, and republishes
itself. OMC removes that mechanic: it **never runs install scripts** and never
imports a package to install it. It compiles the source and computes the verdict
by *reading* it. A lifecycle hook surfaces as a blocked `proc.spawn`; obfuscated
triggers as `dynamic.eval`; reads of `~/.npmrc`/`~/.aws` stay blocked even under
`fs.read:*`; and any secret → network **flow** is denied without an explicit
grant. A built-in 14-day `min-release-age` floor (on by default, tunable or
disabled with `0`) skips the window where a malicious release is live but not yet
yanked. Pinned by regression tests
(`shai_hulud_worm_is_blocked_at_install`).

**Threat model, CI recipe (`omc ci` + `omc audit`), and dev setup: see
[docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md).** A recommended global config is in
[`examples/omc.global.toml`](examples/omc.global.toml).

---

- 📖 **[Quickstart & full reference →](docs/REFERENCE.md)**
- 🧭 **Command surface: native vs compat, and which verb to use: [docs/CLI-SURFACE.md](docs/CLI-SURFACE.md)**
- 🛡️ **Policy DSL (`omc.policy`), complete reference: [docs/POLICY.md](docs/POLICY.md)**
- 🪱 **Supply-chain worm defense + CI/dev recipes: [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md)**
- 🤖 Agent skill: [SKILL.md](SKILL.md)
- 🏗️ Architecture: [docs/oss-microcode-runtime.md](docs/oss-microcode-runtime.md)
- 📦 Releasing: [docs/RELEASING.md](docs/RELEASING.md)
