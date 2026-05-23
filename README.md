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
cargo run -p omc-cli --bin node -- --omc-project-dir /tmp/omc-demo -e "console.log(require('is-odd')(3))"
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo script test
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo add pypi:requests==2.32.3 --allow-all-host
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo python -c "import requests; print(requests.__version__)"
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install --omit-dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install -r requirements/prod.txt
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo install --locked
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo ci
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo run normalizer --version
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm init -y
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm create vite@latest my-app --allow-all-host -- --template react
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm completion
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm help install
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install --save-optional fsevents
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install --save-peer react
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm ci --omit=optional --omit=peer
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install left-pad --workspace @demo/lib
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install --registry https://registry.npmjs.org left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install --dry-run left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/local-util npm link
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm link local-util
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm link ../local-util --save-dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm update --package-lock-only
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install-test -- --watch
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm ci --omit=dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm install-ci-test
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm run --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm run test -- --watch
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm run build --workspace @demo/lib
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm explore left-pad -- pwd
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm audit --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm outdated --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm explain left-pad --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm query ':root > *'
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm ls --depth 0 left-pad --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm prune --omit=dev
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm dedupe
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm rebuild node-sass --ignore-scripts
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm config get registry
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm config set registry https://registry.npmjs.org/
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm config set registry https://project-registry.example/npm --location=project
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm config set registry https://global-registry.example/npm --location=global --globalconfig=global.npmrc
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm cache verify
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm fund --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm pkg get name version
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm version patch --no-git-tag-version
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm pack --pack-destination dist
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm pack left-pad@1.3.0 --pack-destination dist
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm publish --dry-run --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm publish --tag beta --access public --registry https://registry.npmjs.org/
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm unpublish left-pad@1.3.0 --dry-run
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm unpublish left-pad --force --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm deprecate left-pad@1.x "old release line" --dry-run
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm undeprecate left-pad@1.3.0
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm diff --diff left-pad@1.1.0 --diff left-pad@1.3.0 --diff-name-only
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm diff --diff ./packages/lib --diff ./vendor/lib-next --diff-name-only
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm search left-pad --searchlimit=5 --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm star left-pad --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm unstar left-pad --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm stars alice --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm ping --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm whoami --registry https://registry.npmjs.org/
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm login --scope=@company --userconfig=ci.npmrc --auth-token "$NPM_TOKEN"
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm logout --scope=@company --userconfig=ci.npmrc
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm token list --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm token create --password "$NPM_PASSWORD" --name ci-publish --packages-all --packages-and-scopes-permission read-write --expires 30 --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm token revoke a1b2c3 --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm profile get --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm profile set fullname "Alice Example" --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm owner ls left-pad
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm owner add alice left-pad --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm owner rm alice left-pad --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm access get status @company/pkg
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm access set status=public @company/pkg --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm access grant read-write @company:publishers @company/pkg --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm org set @company alice admin --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm org ls @company
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm org rm @company alice --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm team create @company:publishers --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm team add @company:publishers alice --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm team ls @company:publishers
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm dist-tag ls left-pad
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm dist-tag add left-pad@1.3.0 beta --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm dist-tag rm left-pad beta --otp 123456
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm sbom --sbom-format=cyclonedx
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm view left-pad version
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm repo left-pad --browser=false
cargo run -p omc-cli --bin npx -- --omc-project-dir /tmp/omc-demo eslint -- .
cargo run -p omc-cli --bin npx -- --omc-project-dir /tmp/omc-demo --allow-all-host semver@7.6.3 1.2.3
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm root
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo npm bin
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install -r requirements.txt -c constraints.txt
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip help install
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip completion --bash
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install --dry-run --report install-report.json requests==2.32.3
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install --dry-run -e ../local-package
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install requests==2.32.3 --report install-report.json --allow-all-host
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install requests==2.32.3 --allow-all-host
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install -e ../local-package
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install -e 'git+https://example.com/acme/pkg.git@main#egg=acme-pkg'
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install --no-deps ./dist/local_pkg-1.0.0-py3-none-any.whl
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install --target vendor ./dist/local_pkg-1.0.0.tar.gz
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip install ./dist/local_pkg-1.0.0-py3-none-any.whl
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip download -r requirements.txt -d wheelhouse
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip wheel -r requirements.txt -w wheelhouse
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip wheel --no-binary=:all: ./dist/local_pkg-1.0.0.tar.gz -w wheelhouse
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo python -m pip install -e ../local-package
cargo run -p omc-cli --bin pip3 -- --omc-project-dir /tmp/omc-demo freeze
cargo run -p omc-cli --bin python3 -- --omc-project-dir /tmp/omc-demo -m pip freeze
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip freeze
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip show requests
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip list --format=json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip inspect
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip debug --verbose
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip list --outdated --format=json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip list --outdated --format=freeze
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip index versions requests
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip hash ./dist/local_pkg-1.0.0-py3-none-any.whl
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip cache list
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip config get global.index-url
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip config set global.index-url https://pypi.org/simple/
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo pip uninstall -r requirements.txt -y
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo twine check --strict dist/*
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo twine upload -r testpypi dist/*
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo twine upload --repository-url https://upload.pypi.org/legacy/ -u __token__ -p "$PYPI_API_TOKEN" --skip-existing dist/*
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo twine upload --repository-url https://private.example/legacy/ --cert certs/ca.pem --client-cert certs/client.pem -u __token__ -p "$PYPI_API_TOKEN" dist/*
cargo run -p omc-cli --bin twine -- --omc-project-dir /tmp/omc-demo upload --repository-url https://test.pypi.org/legacy/ -u __token__ -p "$TEST_PYPI_API_TOKEN" dist/*
cargo run -p omc-cli --bin python3 -- --omc-project-dir /tmp/omc-demo -m twine upload dist/*
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo list
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo list --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo audit
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo audit --json
cargo run -p omc-cli --bin omc -- --project-dir /tmp/omc-demo remove --npm is-odd left-pad
```

Installing with `--bins` also provides `node`, `npm`, `npx`, `pip`, `pip3`,
`python`, `python3`, and `twine` compatibility binaries. They dispatch directly into OMC
when they are first on `PATH`, so existing scripts can call standard commands
such as `node`, `npm install`, `npm test`, `npx eslint`, `pip install`,
`pip3 install`, `pip freeze`, `python -m pip`, `python3 -m pip`,
`twine check`, `twine upload`, and `python -m twine` without spelling `omc node`, `omc npm`,
`omc pip`, `omc python`, or `omc twine`. They default to the
current directory; use
`OMC_PROJECT_DIR=/path/to/project`, `--project-dir PATH`, or
`--omc-project-dir PATH` for an explicit project root. The Python shims run a
host interpreter with OMC's isolated import path; set `OMC_HOST_PYTHON` if the
host `python3` is not discoverable outside the OMC shim directory. The Node shim
uses the same model; set `OMC_HOST_NODE` if needed.

For existing projects, `install` reads normal project files:

```text
package.json       root/workspace dependencies, devDependencies, optionalDependencies, peers, overrides/resolutions, HTTPS/file tarball deps, local file/link dirs; use --omit-dev for production installs
.npmrc             global/project/user npm registry, scoped registry, and host-scoped auth token configuration; NPM_CONFIG_GLOBALCONFIG selects a custom global file, NPM_CONFIG_USERCONFIG selects a custom user file, and NPM_CONFIG_REGISTRY / npm_config_registry override the default registry
package-lock.json  exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
npm-shrinkwrap.json exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
yarn.lock          Yarn Classic exact versions, resolved tarball URLs, and integrity hashes for uniquely locked npm packages
pnpm-lock.yaml     pnpm importer dependencies, exact versions, resolved tarball URLs, and integrity hashes
pip.conf           PyPI index-url, extra-index-url, find-links, no-index, no-binary, and only-binary configuration
.pypirc            PyPI/TestPyPI/private repository upload URLs, ca_cert/client_cert TLS settings, plus username/password or token credentials for Twine-compatible upload
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
use global/project/user `.npmrc` registry, scoped registry, auth token settings, npm globalconfig/userconfig env vars, and npm registry env vars for npm
use `omc.toml` PyPI simple-index settings for OMC-managed PyPI adds
use project/user `pip.conf` PyPI simple-index settings when no project index is set
use `PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` when no project PyPI index is set
use pip-style `find-links`, `no-index`, and binary-format config/env values for wheelhouses
verify npm shasum/integrity and PyPI sha256 when the registry provides them
use package-lock.json/npm-shrinkwrap.json/yarn.lock/pnpm-lock.yaml npm resolved tarball URLs and integrity hashes when present
cache the source artifact under .omc/cache
profile runtime source files into OMC capability findings, including common static env and URL targets
run the OMC verifier with deny-by-default policy
write an OMC artifact under .omc/artifacts
sign generated OMC artifacts and verify signatures during locked installs
update omc.toml and omc.lock only when accepted
support lock-only npm compatibility installs that update omc.toml/omc.lock
without extracting node_modules
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
global/project/user `pip.conf`, `PIP_CONFIG_FILE`, `PIP_INDEX_URL`, and
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
- global, project, and user `.npmrc` support for `registry`, `@scope:registry`,
  and host-scoped `_authToken` npm registry access, plus `NPM_CONFIG_REGISTRY` /
  `npm_config_registry` default-registry overrides, `NPM_CONFIG_GLOBALCONFIG` /
  `npm_config_globalconfig` global `.npmrc` path selection, and
  `NPM_CONFIG_USERCONFIG` / `npm_config_userconfig` user `.npmrc` path selection
- project `omc.toml` PyPI simple-index support for `pypi-index-url` and
  `pypi-extra-index-urls`
- global/project/user `pip.conf` and `PIP_CONFIG_FILE` PyPI support for `index-url`,
  `extra-index-url`, `find-links`, `no-index`, `no-binary`, and `only-binary`
- pip-style `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`,
  `PIP_NO_INDEX`, `PIP_NO_BINARY`, and `PIP_ONLY_BINARY` support when no
  project PyPI index is configured
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
- npm save-location flags for OMC manifests: `--save-prod`/`-P`,
  `--save-dev`/`-D`, `--save-optional`/`-O`, and `--save-peer`
- npm omit/include flags for install selection:
  `--omit=dev|optional|peer` and `--include=dev|optional|peer`
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
  `--no-binary`, `--prefer-binary`, enforced `--require-hashes`, local editable/direct/bare
  directory paths with selected extras, and common Python environment markers
- `pip download` and `pip wheel` compatibility for registry requirements,
  requirement files, hashes, direct wheel archives, and direct source
  distributions; `pip wheel` populates the wheelhouse with safe source
  distributions when a build would otherwise be required
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
- `omc add`, `omc add --dev`, `omc add --optional`, `omc add --peer`, and
  `omc remove` for one or more OMC-managed dependencies, with `--npm` and
  `--pypi` shorthands for unprefixed specs
- `[dev-dependencies]`, `[optional-dependencies]`, and `[peer-dependencies]`
  support in `omc.toml`, including `omc install --omit-dev`
- `omc install` / `omc ci` support for `--omit-optional` and `--omit-peer`
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
- `omc npm` compatibility commands for common `install`, `link` / `ln`, `update` / `up` /
  `upgrade`, `install-test` / `it`, `ci`, `install-ci-test` / `cit`, `prune`, `dedupe`, `rebuild`, `test`, `start`, `stop`, `restart`,
  `run`, `exec`, `init`, `remove`, `bin`, `root`, `prefix`, `audit` / `audit --json`,
  `help`, `fund` / `fund --json`, `cache verify/ls/rm/clean --force`, `pkg get/set/delete`, `version`,
  `pack`, `publish`, `unpublish`, `deprecate`, `undeprecate`, `diff`, `search` / `find`,
  `star`, `unstar`, `stars`, `ping`, `whoami`, `login` / `adduser`, `logout`,
  `token list/create/revoke`, `profile get/set`, `owner ls/add/rm`,
  `access list/get/set/grant/revoke`, `org set/rm/ls`, `team create/destroy/add/rm/ls`, `dist-tag ls/add/rm`, `sbom --sbom-format=cyclonedx|spdx`, `config get/set/delete/list`, `get`,
  `view` / `info` / `show`, `query`, `docs`, `repo`, `bugs`, `home`,
  `list` / `ls` / `ll` / `la`, including `--json`, common depth/omit/workspace
  flags, and package-name filters; `explain` / `why`,
  and `outdated` / `outdated --json` flows without delegating to npm, plus a direct
  `npm` compatibility binary and direct `npx` compatibility binary for
  project-local executable flows; direct local npm tarballs and local package
  directories are accepted as install/update/link inputs; `npm link`
  supports current-package registration, local directory shortcut links, and
  name-based links from OMC's user link store; `npm pack` supports local
  package directories and registry specs; `npm diff` supports registry package
  specs, local package directories, and npm tarballs; common `npm exec` / `npx`
  flags such as `--yes`, `--no-install`, `--package`, `--cache`,
  `--registry`, `--allow`, and `--allow-all-host` are parsed; direct `npx`
  package specs and explicit `--package` specs are installed into a temporary
  verified OMC project before dispatching to the requested executable; `--no-save`,
  `--package-lock-only`, `--package-lock=false`, `--dry-run`, `--registry`,
  `--omit=...`, `--include=...`, and common audit/fund/peer/install-strategy flags are
  understood for install/ci compatibility; `npm install --workspace ...`
  saves into selected workspace `package.json` files while installing the root
  OMC graph; common global npm flags such as
  `--silent`, `--loglevel`, and `--cache` are accepted before the subcommand,
  while `--registry`, `--userconfig`, and `--json` are forwarded to subcommands
  that support them; package scripts receive npm-style
  lifecycle/package environment variables such as `npm_lifecycle_event`,
  `npm_lifecycle_script`, `npm_package_name`, `npm_package_version`,
  `npm_package_config_*`, `npm_package_bin_*`, `npm_package_json`,
  `npm_config_user_agent`, and `INIT_CWD`; `npm run` lists root or workspace
  scripts in text or JSON mode; `pre<script>` / `post<script>`
  lifecycle hooks are executed around the requested script; common script and
  workspace flags such as `--if-present`, `--workspace`, `--workspaces`,
  `--include-workspace-root`, `--silent`, `-s`, and `--loglevel=silent` are
  understood
- `omc pip` compatibility commands for common `install`, `uninstall`, `freeze`,
  `download`, `check`, `debug`, `help`, `inspect`, `show`, `hash`, `cache dir/list/remove/purge`,
  `wheel`, `index versions`, `config get/set/unset/list`, and
  `list --format=columns|freeze|json` flows, including `pip list --outdated`
  with columns, JSON, and freeze output,
  `-r`, index URL,
  constraints, extra-index, find-links, no-index,
  require-hashes, no-deps, target-directory, trusted-host, retry/timeout,
  reinstall, warning, build-isolation, and binary-policy install flags without
  delegating to pip; common global pip flags such as
  `--disable-pip-version-check`, `--quiet`, `--timeout`, `--retries`,
  `--trusted-host`, `--cert`, `--client-cert`, and `--cache-dir` are accepted
  before the subcommand; `pip uninstall -r requirements.txt` removes named
  requirements from the OMC manifest and reinstalls the remaining graph; common
  `pip install --report path` JSON reports and registry/archive
  `pip install --dry-run` resolution, including local editable paths and VCS
  requirements, without writing the current OMC manifest, lockfile, or
  site-packages; read-only `pip freeze` / `pip list` scope flags
  such as `--all`, `--local`,
  `--user`, `--path`, `--exclude`, and `--exclude-editable` are accepted;
  direct `pip install -e PATH` and `pip install ./path` local directory
  installs, including selected extras such as
  `pip install -e '.[dev]'`; direct
  `pip install ./archive.whl`, `./archive.tar.gz`, and HTTPS archive URL
  installs; editable git/VCS installs such as `pip install -e git+...#egg=name`;
  `omc python -m pip ...` dispatches to the same compatibility path;
  direct `pip` / `pip3` compatibility binaries; and direct `python` / `python3`
  compatibility binaries for isolated interpreter use and `python -m pip` flows
- isolated `omc python` execution that uses OMC site-packages without ambient
  user/global Python site-packages or startup/hook environment variables
- isolated Node execution wrappers that remove ambient `NODE_PATH` module
  resolution and `NODE_OPTIONS` preloads outside the project install tree,
  including a direct `node` compatibility binary
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
