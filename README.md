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
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add npm:left-pad@1.3.0
cargo run -p omc-cli -- --project-dir /tmp/omc-demo add pypi:idna==3.7
cargo run -p omc-cli -- --project-dir /tmp/omc-demo audit
```

What `add` does:

```text
resolve exact package version from npm or PyPI
download the registry artifact without executing it
verify PyPI sha256 when the registry provides it
cache the source artifact under .omc/cache
profile runtime source files into OMC capability findings
run the OMC verifier with deny-by-default policy
write an OMC artifact under .omc/artifacts
update omc.toml and omc.lock only when accepted
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

This is still a prototype. It replaces install-time execution with registry
resolution, source caching, OMC artifact generation, capability verification,
and lockfile recording. It does not yet build a complete dependency graph,
execute packages as cells for real applications, or expose compatibility shims
for Node/Python imports.

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
- source artifact download and cache
- `omc.toml` and `omc.lock`
- runtime source profiling into capability findings
- explicit CLI grants for accepted host authority

Not implemented yet:

- real JavaScript or Python frontend
- package artifact signing
- transitive dependency graph solving
- structured microcode serialization
- full control-flow graph verification
- imports/linking across package cells
- native/Wasm/Cranelift backend
- Node/Python compatibility shims that execute real applications through OMC

## Useful Commands

```bash
cargo test
cargo run -p omc-demo
cargo run -p omc-cli -- --help
```
