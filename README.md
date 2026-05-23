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
cargo install --path crates/omc-cli --bins

cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo init --name demo
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo allow http:api.example.com env:API_TOKEN
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add --npm is-odd@3.0.1 left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add --npm is-number@7.0.0 --dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo node -e "console.log(require('is-odd')(3))"
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo script test
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add pypi:requests==2.32.3 --allow-all-host
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo python -c "import requests; print(requests.__version__)"
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install --omit-dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install -r requirements/prod.txt
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install --locked
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo ci
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo run normalizer --version
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm ci --omit=dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm run test -- --watch
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm root
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm bin
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install -r requirements.txt -c constraints.txt
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install requests==2.32.3 --allow-all-host
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install -e ../local-package
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install ./dist/local_pkg-1.0.0-py3-none-any.whl
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip freeze
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip show requests
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip list --format=json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo list
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo list --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo audit
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo audit --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo remove --npm is-odd left-pad
```

Installing with `--bins` also provides `npm` and `pip` compatibility binaries.
They dispatch directly into OMC when they are first on `PATH`, so existing
scripts can call `npm install`, `npm test`, `pip install`, `pip freeze`, and
related supported commands without spelling `omc npm` or `omc pip`. They default
to the current directory; use `OMC_PROJECT_DIR=/path/to/project`,
`--project-dir PATH`, or `--omc-project-dir PATH` for an explicit project root.

For existing projects, `install` reads normal project files:

```text
package.json       root/workspace dependencies, devDependencies, optionalDependencies, peers, overrides/resolutions, HTTPS/file tarball deps, local file/link dirs; use --omit-dev for production installs
.npmrc             npm registry, scoped registry, and host-scoped auth token configuration
package-lock.json  exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
npm-shrinkwrap.json exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
yarn.lock          Yarn Classic exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
pnpm-lock.yaml     pnpm importer dependencies, exact versions, resolved tarball URLs, and integrity hashes
pip.conf           PyPI index-url, extra-index-url, find-links, and no-index configuration
requirements.txt  PyPI requirements, direct wheel/sdist URLs and paths, VCS git dependencies, hashes, extras, local editable/direct/bare directory paths, -r includes, -c constraints, markers, simple indexes, find-links wheel/sdist archives
requirements-dev.txt / dev-requirements.txt  dev requirements read unless --omit-dev is set
requirements/base.txt / requirements/dev.txt  common requirements directory layout; dev is read unless --omit-dev is set
Pipfile           Pipenv packages/dev-packages, source indexes, extras, markers, git dependencies, local paths, wheel/sdist file dependencies, and scripts
Pipfile.lock      Pipenv default/develop package pins, git dependencies, local paths, extras, markers, sources, and sha256 hashes
uv.lock           uv project requirements, dev requirements, local path sources, exact package pins, and hashes
pylock.toml       standardized Python lock package pins, markers, and hashes
pyproject.toml    PEP 621 project dependencies, selected optional groups, dependency-groups, uv local/workspace sources, direct wheel/sdist URL/path dependencies, git dependencies, local path deps
pyproject.toml    Poetry dependencies, dev groups, optional groups, extras, source indexes, wheel/sdist URL/path dependencies, git dependencies, local path deps
poetry.lock       exact PyPI versions and file hashes for locked Poetry packages
setup.cfg         legacy setuptools install_requires and selected extras_require
setup.py          static setuptools install_requires and selected extras_require
```

What `add` does:

```text
resolve package version ranges from npm or PyPI
walk runtime dependencies recursively
download the registry artifact without executing it
use project/user `.npmrc` registry, scoped registry, and auth token settings for npm
use `omc.toml` PyPI simple-index settings for OMC-managed PyPI adds
use project/user `pip.conf` PyPI simple-index settings when no project index is set
use `PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` when no project PyPI index is set
use pip-style `find-links` and `no-index` config/env values for wheelhouses
verify npm shasum/integrity and PyPI sha256 when the registry provides them
use package-lock.json/npm-shrinkwrap.json/yarn.lock/pnpm-lock.yaml npm resolved tarball URLs and integrity hashes when present
cache the source artifact under .omc/cache
profile runtime source files into OMC capability findings, including common static env and URL targets
run the OMC verifier with deny-by-default policy
write an OMC artifact under .omc/artifacts
sign generated OMC artifacts and verify signatures during locked installs
update omc.toml and omc.lock only when accepted
install npm packages into node_modules
install PyPI wheels and pure Python sdists into .omc/python/site-packages
verify cached archive sha256 from omc.lock before extracting locked installs
install npm package bins, including root project bins, into node_modules/.bin
link npm workspace/local directory packages into node_modules and node_modules/.bin
persist direct npm local directory installs in omc.toml, including dev-only
local paths, and link them during install/ci
clone Python git/VCS dependencies into .omc/python/vcs and install them as isolated local imports
record resolved Python git/VCS commits in omc.lock and reuse those commits for --locked/ci installs
cache pinned Python git/VCS checkout archives under .omc/cache/python-vcs for locked restore
install Python console_scripts/gui_scripts from wheels, the root Python project, and pyproject/setup.cfg/setup.py local path packages into .omc/python/bin
prune stale lockfile entries and installed packages during install
```

Default policy denies host authority. A package such as `esbuild`, which has a
postinstall script and host access, is blocked:

```bash
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add npm:esbuild@0.19.12
```

Intentional grants are explicit and recorded in the generated artifact and
lockfile:

```bash
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add npm:esbuild@0.19.12 --allow-all-host
```

Fine-grained grants are supported too:

```bash
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add npm:some-client@1.0.0 \
  --allow http:api.example.com \
  --allow env:API_TOKEN
```

Projects can persist approved grants in `omc.toml`:

```toml
[policy]
allow = ["http:api.example.com", "env:API_TOKEN"]
```

Projects can also persist PyPI index selection for `omc add` and
`omc install`:

```toml
[registries]
pypi-index-url = "https://pypi.org/simple"
pypi-extra-index-urls = ["https://packages.example/simple"]
```

If the project does not set a PyPI index, OMC also honors pip-style
project/user `pip.conf`, `PIP_CONFIG_FILE`, `PIP_INDEX_URL`, and
`PIP_EXTRA_INDEX_URL` settings. Wheelhouse settings such as `find-links`,
`no-index`, `PIP_FIND_LINKS`, and `PIP_NO_INDEX` feed the same offline resolver.

This is still a prototype. It replaces install-time execution with registry
resolution, source caching, OMC artifact generation, capability verification,
lockfile recording, and local install trees for Node/Python imports. It does
not yet execute package code inside OMC cells for real applications, implement
the complete npm/PyPI resolver surface, or build native Python packages.

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
- project `omc.toml` PyPI simple-index support for `pypi-index-url` and
  `pypi-extra-index-urls`
- project/user `pip.conf` and `PIP_CONFIG_FILE` PyPI support for `index-url`,
  `extra-index-url`, `find-links`, and `no-index`
- pip-style `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, and
  `PIP_NO_INDEX` support when no project PyPI index is configured
- credential-bearing PyPI simple-index URLs are used for downloads without
  recording those credentials in `omc.lock`
- PyPI dependency range resolution with local `python3` `Requires-Python`
  filtering
- recursive runtime dependency locking
- root and npm workspace `package.json` dependency/devDependency ingestion,
  including HTTPS/local `file:` `.tgz` / `.tar.gz` tarball dependencies and
  local `file:` / `link:` directory dependencies
- npm `overrides` and Yarn-style `resolutions` as version constraints
- npm workspace and local directory package linking into `node_modules` and
  `node_modules/.bin`
- direct `npm install ./package.tgz`, `npm install file:./package.tgz`, and
  `npm install ./local-package` compatibility paths through OMC-managed
  artifacts or local links; local package directories installed with `-D`
  are omitted by `--omit-dev`
- production-style `omc install --omit-dev` installs
- explicit `omc install -r FILE` and `omc ci -r FILE` requirements-file inputs
- npm `optionalDependencies` and required `peerDependencies` ingestion
- npm registry `optionalDependencies` and required `peerDependencies` resolution
- npm platform filtering for optional dependencies using package `os`, `cpu`,
  and `libc` metadata
- npm bundled dependency metadata so bundled packages are not resolved from the
  registry a second time
- `package-lock.json`, `npm-shrinkwrap.json`, and Yarn Classic `yarn.lock`
  exact-version constraints, resolved tarball URLs, and integrity verification
  for uniquely locked npm packages
- `pnpm-lock.yaml` importer dependency ingestion plus exact-version
  constraints, resolved tarball URLs, and integrity verification for uniquely
  locked npm packages
- `requirements.txt`, `requirements/base.txt`, `requirements-dev.txt`,
  `dev-requirements.txt`, and `requirements/dev.txt` ingestion with hashes,
  line continuations, extras,
  direct wheel/sdist URLs and paths, git VCS dependencies with refs and
  subdirectories, recursive `-r` includes, `-c` constraints, `--index-url` /
  `--extra-index-url` simple indexes, `--find-links` / `-f` local wheel/sdist
  archives or HTML pages, `--no-index`, `--trusted-host`, `--only-binary`,
  `--prefer-binary`, enforced `--require-hashes`, local editable/direct/bare
  directory paths, and common Python environment markers
- unsupported requirements entries and unsupported direct archive formats fail
  closed instead of being silently ignored
- `Pipfile` ingestion for Pipenv packages/dev-packages, source indexes, extras,
  markers, git dependencies, local path dependencies, and wheel/sdist file
  dependencies when `Pipfile.lock` is absent
- Pipfile `[scripts]` support through `omc script`
- `Pipfile.lock` ingestion for Pipenv default/develop package pins, git
  dependencies, local paths, extras, markers, `_meta.sources` simple indexes,
  and sha256 hashes
- `uv.lock` ingestion for uv project requirements, dev requirements, local path
  sources, exact-version constraints, and sdist/wheel sha256 hashes
- `pylock.omc.toml` / `pylock.toml` ingestion for standardized Python lock
  package pins, markers, and archive/wheel sha256 hashes
- `pyproject.toml` PEP 621 dependency ingestion with `omc install --extra`
  for selected optional dependency groups, standardized `[dependency-groups]`
  with nested `include-group` support, `[tool.uv.sources]` local/workspace path
  sources, direct wheel/sdist URLs/paths, git dependencies, and local path
  dependencies
- Poetry `pyproject.toml` dependency ingestion, including
  `[tool.poetry.dependencies]`, old `[tool.poetry.dev-dependencies]`,
  dependency groups, selected optional groups, selected extras,
  `[[tool.poetry.source]]` simple indexes, direct HTTPS wheel/sdist URLs, git
  dependencies, local wheel/sdist paths, and local path dependencies
- `poetry.lock` exact-version constraints and sha256 file hash verification for
  locked PyPI packages
- `setup.cfg` `install_requires` ingestion plus selected
  `[options.extras_require]` extras, including git dependencies
- static `setup.py` `install_requires` ingestion plus selected
  `extras_require` extras, including git dependencies
- PyPI extras resolution for dependencies gated by `extra == "..."`
- source artifact download and cache
- `omc.toml` and `omc.lock`
- structured OMC microcode serialization inside generated package artifacts
- local Ed25519 signatures for generated package artifacts, verified before
  locked package extraction
- persistent `[policy].allow` grants in `omc.toml`
- `omc allow` for editing persistent project policy grants
- `omc add`, `omc add --dev`, and `omc remove` for one or more OMC-managed
  dependencies, with `--npm` and `--pypi` shorthands for unprefixed specs
- `[dev-dependencies]` support in `omc.toml`, including `omc install --omit-dev`
- install-time pruning so `omc.lock`, `node_modules`, and Python site-packages
  converge to current project manifests
- locked/offline `omc install --locked` installs that validate `omc.lock`
  against current project manifests without registry resolution
- Python git/VCS dependency lock entries that pin the resolved commit used by
  `omc install --locked` and `omc ci`
- Python git/VCS source archive cache used to restore pinned locked checkouts
  when the live checkout is missing
- `omc ci` as a lockfile-only install command for clean/CI workflows
- install-time sha256 verification for cached archives before package extraction
- text and JSON `omc list` output for locked packages
- text and JSON audit output for locked package verdicts
- `node_modules` installation for npm tarballs
- nested `node_modules` installation for conflicting npm dependency versions
- npm alias dependencies such as `name: npm:other-name@range`
- `.omc/python/site-packages` installation for PyPI wheels and pure Python
  `.tar.gz`, `.tgz`, and `.zip` source distributions without executing build
  scripts
- platform-compatible PyPI wheel selection for native wheels
- native/source build execution remains denied until build isolation and
  native-extension policy exist
- npm bin links, including root project bins and linked workspace/local package
  bins, and Python console/gui script shims from wheels and
  pyproject/setup.cfg/setup.py local path packages
- editable-style root Python project imports and scripts when
  pyproject/setup.cfg/setup.py metadata exists
- `omc node`, `omc python`, `omc script`, and `omc run` wrappers, including
  package.json and Pipfile project scripts
- `omc npm` compatibility commands for common `install`, `ci`, `test`,
  `start`, `stop`, `restart`, `run`, `exec`, `remove`, `bin`, `root`,
  `prefix`, and `list` / `list --json` flows without delegating to npm, plus a
  direct `npm` compatibility binary; direct local npm tarballs and local
  package directories are accepted as install inputs
- `omc pip` compatibility commands for common `install`, `uninstall`, `freeze`,
  `show`, and `list --format=columns|freeze|json` flows, including `-r`, index
  URL, constraints, extra-index, find-links, and no-index install flags without
  delegating to pip; direct `pip install -e PATH` and `pip install ./path`
  local directory installs; direct `pip install ./archive.whl`,
  `./archive.tar.gz`, and HTTPS archive URL installs; and a direct `pip`
  compatibility binary
- isolated `omc python` execution that uses OMC site-packages without ambient
  user/global Python site-packages or startup/hook environment variables
- isolated Node execution wrappers that remove ambient `NODE_PATH` module
  resolution and `NODE_OPTIONS` preloads outside the project install tree
- runtime source profiling into capability findings
- static env-read plus URL-host lowering into OMC env-to-network flow checks
- explicit CLI grants for accepted host authority

Not implemented yet:

- real JavaScript or Python frontend
- full control-flow graph verification
- imports/linking across package cells
- native/Wasm/Cranelift backend
- full npm peer placement semantics beyond current required-peer handling
- advanced requirements-file semantics beyond supported git, direct archive,
  hash, marker, include, constraint, index, and find-links handling
- Poetry dependency forms beyond direct wheel/sdist URLs, git dependencies,
  local wheel/sdist files, and local path directories
- Python sdist build isolation and native extension policy beyond pure source
  extraction
- execution of package code inside OMC cells for real applications

## Useful Commands

```bash
cargo test
cargo run -p omc-demo
cargo run -p omc-cli --bin omc -- --help
```
