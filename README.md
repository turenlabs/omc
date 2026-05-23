# OMC: OSS Microcode

OMC is a Rust runtime experiment for hostile open-source dependencies.

The thesis is narrow: packages should not execute as JavaScript, Python, shell,
native code, or editor extension code with ambient authority. They should lower
into a small dependency-native instruction set first, then pass through a
verifier, a capability broker, and a labeled data-flow runtime.

```text
npm / PyPI / extension source
        |
language compiler front end
        |
OMC bytecode
        |
Rust verifier
        |
Rust runtime cell
        |
capability broker
        |
host OS, network, filesystem, secrets
```

This repository currently contains the runtime seed, not a full npm or Python
frontend.

## Workspace

```text
crates/
  omc-format/   bytecode, values, modules, capability instructions
  omc-taint/    first-class labels for env, file, token, network, and mixed data
  omc-cap/      deny-by-default policy and capability broker
  omc-verify/   static verifier for bytecode shape, capability grants, and flows
  omc-vm/       small stack interpreter with fuel and brokered host operations
  omc-registry/ registry clients, cache, lockfile, and source profiler
  omc-cli/      package-manager prototype binary
  omc-demo/     runnable exfiltration demo
```

The missing future crates are intentional: `omc-loader`, `omc-memory`,
`omc-policy`, `omc-linker`, `omc-audit`, and `omc-host` should grow out of the
runtime contracts instead of landing as empty names.

## Runtime Rules

Packages start with zero permissions.

No package talks to Rust `std` directly. No package talks to the OS directly. No
package gets ambient authority.

Dangerous behavior must compile into loud capability instructions:

```text
CAP_ENV_READ
CAP_FS_READ
CAP_FS_WRITE
CAP_HTTP_REQUEST
CAP_PROC_SPAWN
CAP_DYNAMIC_EVAL
```

The broker enforces capability grants and data-flow labels. A value read from
`NPM_TOKEN` carries `env:NPM_TOKEN`. Sending that value to a network host is not
malware detection; it is an illegal information flow unless policy explicitly
allows it.

## Demo

Run the verifier demo:

```bash
cargo run -p omc-demo
```

Expected result:

```text
Package: date-helper@1.2.4
Claimed type: HostCapability

Compile result: FAILED

Verifier findings:
  - formatDate[1]: env:NPM_TOKEN may not flow to network:cdn-update-service.example
```

The demo grants both `env.read:NPM_TOKEN` and
`http:cdn-update-service.example`, but it does not grant the data-flow edge from
that env value to that network sink. The capability exists; the flow is still
illegal.

## Package Manager Prototype

The `omc` CLI is the first working slice of a PyPI/npm replacement:

```bash
cargo run -p omc-cli -- --project-dir /tmp/omc-demo init --name demo
cargo run -p omc-cli -- --project-dir /tmp/omc-demo allow http:api.example.com env:API_TOKEN
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:is-odd@3.0.1
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:left-pad@1.3.0 --dev
cargo run -p omc-cli -- --project-dir /tmp/omc-demo node -e "console.log(require('is-odd')(3))"
cargo run -p omc-cli -- --project-dir /tmp/omc-demo script test
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add pypi:requests==2.32.3 --allow-all-host
cargo run -p omc-cli -- --project-dir /tmp/omc-demo python -c "import requests; print(requests.__version__)"
cargo run -p omc-cli -- --project-dir /tmp/omc-demo install --omit-dev
cargo run -p omc-cli -- --project-dir /tmp/omc-demo install --locked
cargo run -p omc-cli -- --project-dir /tmp/omc-demo run normalizer --version
cargo run -p omc-cli -- --project-dir /tmp/omc-demo list
cargo run -p omc-cli -- --project-dir /tmp/omc-demo list --json
cargo run -p omc-cli -- --project-dir /tmp/omc-demo audit
cargo run -p omc-cli -- --project-dir /tmp/omc-demo audit --json
cargo run -p omc-cli -- --project-dir /tmp/omc-demo remove npm:is-odd
```

For existing projects, `install` reads normal project files:

```text
package.json       dependencies, devDependencies, optionalDependencies, peers; use --omit-dev for production installs
.npmrc             npm registry, scoped registry, and host-scoped auth token configuration
package-lock.json  exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
requirements.txt  PyPI requirements, direct wheel URLs, hashes, extras, -r includes, -c constraints, markers
pyproject.toml    PEP 621 project dependencies, selected optional groups
pyproject.toml    Poetry dependencies, dev groups, optional groups, and extras
poetry.lock       exact PyPI versions and file hashes for locked Poetry packages
```

What `add` does:

```text
resolve package version ranges from npm or PyPI
walk runtime dependencies recursively
download the registry artifact without executing it
use project/user `.npmrc` registry, scoped registry, and auth token settings for npm
verify npm shasum/integrity and PyPI sha256 when the registry provides them
use package-lock.json npm resolved tarball URLs and integrity hashes when present
cache the source artifact under .omc/cache
profile runtime source files into OMC capability findings
run the OMC verifier with deny-by-default policy
write an OMC artifact under .omc/artifacts
update omc.toml and omc.lock only when accepted
install npm packages into node_modules
install PyPI wheels into .omc/python/site-packages
verify cached archive sha256 from omc.lock before extracting locked installs
install npm package bins into node_modules/.bin
install Python console_scripts into .omc/python/bin
prune stale lockfile entries and installed packages during install
```

Default policy denies host authority. A package such as `esbuild`, which has a
postinstall script and host access, is blocked:

```bash
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:esbuild@0.19.12
```

Intentional grants are explicit and recorded in the generated artifact and
lockfile:

```bash
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:esbuild@0.19.12 --allow-all-host
```

Fine-grained grants are supported too:

```bash
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:some-client@1.0.0 \
  --allow http:api.example.com \
  --allow env:API_TOKEN
```

Projects can persist approved grants in `omc.toml`:

```toml
[policy]
allow = ["http:api.example.com", "env:API_TOKEN"]
```

This is still a prototype. It replaces install-time execution with registry
resolution, source caching, OMC artifact generation, capability verification,
lockfile recording, and local install trees for Node/Python imports. It does
not yet execute package code inside OMC cells for real applications, implement
the complete npm/PyPI resolver surface, or build native/sdist packages.

## Current MVP Boundaries

Supported now:

- integers, strings, arrays, maps, booleans, and unit values
- stack bytecode with simple locals and local calls
- explicit capability instructions
- deny-by-default policy
- labels for env, file, token, network, and mixed values
- verifier checks for shape, declared `Pure` behavior, capability grants, and
  simple stack-visible flows
- interpreter checks the same broker policy at runtime
- npm and PyPI exact-version resolution
- npm semver range resolution for common dependency ranges
- project and user `.npmrc` support for `registry`, `@scope:registry`, and
  host-scoped `_authToken` npm registry access
- PyPI dependency range resolution with local `python3` `Requires-Python`
  filtering
- recursive runtime dependency locking
- `package.json` dependency/devDependency ingestion
- production-style `omc install --omit-dev` installs
- npm `optionalDependencies` and required `peerDependencies` ingestion
- npm registry `optionalDependencies` and required `peerDependencies` resolution
- npm platform filtering for optional dependencies using package `os`, `cpu`,
  and `libc` metadata
- npm bundled dependency metadata so bundled packages are not resolved from the
  registry a second time
- `package-lock.json` exact-version constraints, resolved tarball URLs, and
  integrity verification for uniquely locked npm packages
- `requirements.txt` ingestion with hashes, line continuations, extras,
  direct wheel URLs, recursive `-r` includes, `-c` constraints, and common
  Python environment markers
- unsupported requirements entries such as editable installs, index
  configuration, VCS URLs, and non-wheel direct URLs fail closed instead of
  being silently ignored
- `pyproject.toml` PEP 621 dependency ingestion with `omc install --extra`
  for selected optional dependency groups
- Poetry `pyproject.toml` dependency ingestion, including
  `[tool.poetry.dependencies]`, old `[tool.poetry.dev-dependencies]`,
  dependency groups, selected optional groups, and selected extras
- `poetry.lock` exact-version constraints and sha256 file hash verification for
  locked PyPI packages
- PyPI extras resolution for dependencies gated by `extra == "..."`
- source artifact download and cache
- `omc.toml` and `omc.lock`
- persistent `[policy].allow` grants in `omc.toml`
- `omc allow` for editing persistent project policy grants
- `omc add`, `omc add --dev`, and `omc remove` for OMC-managed dependencies
- `[dev-dependencies]` support in `omc.toml`, including `omc install --omit-dev`
- install-time pruning so `omc.lock`, `node_modules`, and Python site-packages
  converge to current project manifests
- locked/offline `omc install --locked` installs that validate `omc.lock`
  against current project manifests without registry resolution
- install-time sha256 verification for cached archives before package extraction
- text and JSON `omc list` output for locked packages
- text and JSON audit output for locked package verdicts
- `node_modules` installation for npm tarballs
- nested `node_modules` installation for conflicting npm dependency versions
- npm alias dependencies such as `name: npm:other-name@range`
- `.omc/python/site-packages` installation for PyPI wheels
- platform-compatible PyPI wheel selection for native wheels
- fail-closed rejection for PyPI source distributions until build isolation and
  native-extension policy exist
- npm bin links and Python console script shims
- `omc node`, `omc python`, `omc script`, and `omc run` wrappers
- isolated `omc python` execution that uses OMC site-packages without ambient
  user/global Python site-packages or startup/hook environment variables
- isolated Node execution wrappers that remove ambient `NODE_PATH` module
  resolution and `NODE_OPTIONS` preloads outside the project install tree
- runtime source profiling into capability findings
- explicit CLI grants for accepted host authority

Not implemented yet:

- real JavaScript or Python frontend
- package artifact signing
- structured microcode serialization
- full control-flow graph verification
- imports/linking across package cells
- native/Wasm/Cranelift backend
- full npm peer placement semantics beyond current required-peer handling
- advanced requirements-file semantics such as editable installs, VCS URLs,
  non-wheel direct URLs, and index configuration beyond fail-closed rejection
- Poetry direct path/git/url/file dependencies beyond fail-closed rejection
- Python sdist build isolation and native extension policy beyond fail-closed
  rejection
- execution of package code inside OMC cells for real applications

## Useful Commands

```bash
cargo test
cargo run -p omc-demo
cargo run -p omc-cli -- --help
```
