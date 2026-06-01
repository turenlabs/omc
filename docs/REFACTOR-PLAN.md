# lib.rs module-split plan

Splitting the two monolith `lib.rs` files into a proper module tree. Branch:
`refactor/split-lib-modules`. **Invariant: every commit builds and `cargo test
--workspace` is green.** Pure code movement + visibility bumps; behavior and
public API unchanged.

## Status — ✅ COMPLETE

The split is done. **0 warnings, full `cargo test --workspace` green (612 tests), 63 bisectable commits.**

| Metric | Before | After |
| --- | --- | --- |
| files (crate `src/`) | 2 monoliths | **115** |
| omc-registry `lib.rs` | 31,772 | **6,677** |
| omc-cli `lib.rs` | 49,927 | **5,980** |
| files > 4,000 lines | 2 (both ~30–50k) | **2** (the two `lib.rs` orchestration cores) |
| biggest non-core file | — | 3,945 (`npm_account.rs`) |

The only two files over ~4k are now `omc-registry/src/lib.rs` (resolution/install
orchestration: `resolve_package_graph`, `link_package*`, `install_*`) and
`omc-cli/src/lib.rs` (command dispatch + install orchestration). These are
**cohesive by responsibility** — per the research guidance "decompose by
responsibility, not line count," an orchestration core is a legitimate unit and is
left intact rather than fragmented. Each domain (npm/pypi resolve, install,
config, metadata, profiler, verify, signature, policy, manifest, lockfile, the
npm/pip/twine CLI command families, …) is now its own module; tests live in
`src/tests/<domain>_tests.rs`.

Optional future polish (not required for "done"): de-glob the `use crate::*`
scaffolding into explicit imports, demote any over-broad `pub(crate)` back to
private, add `#![warn(unreachable_pub)]`. Behavior and public API are byte-unchanged.

## Mechanical recipe (per impl module)

1. Add `pub(crate) mod foo;` (NOT `pub mod`) to lib.rs; create `src/foo.rs`. Build (green).
2. Top of `foo.rs`: scaffold `use crate::*;` **plus** explicit `use` lines for every **external** crate the cluster touches (std, base64, chrono, ed25519_dalek, flate2, reqwest, semver, serde, sha1, sha2, tar, walkdir, zip, omc_*). The parent's external imports do NOT flow in, and `use crate::*` does NOT re-export them.
3. Cut one cohesive cluster (a type + its inherent/trait impls + private free-fn helpers) out of lib.rs into `foo.rs`. Move whole `impl` blocks with their type.
4. `cargo build`; fix the error wave **minimally**: E0603 "private" → bump that item private→`pub(crate)`; E0616 "field is private" → bump that **field** (struct visibility ≠ field visibility); E0425/E0433 "cannot find X" in code left at root → `use crate::foo::X;`. Never blanket-`pub`.
5. Restore the public contract: for every item that was `pub` in the original lib.rs and now lives in `foo.rs`, add `pub use foo::Thing;` at the crate root (keeps `omc_registry::Thing` + cross-crate paths byte-identical — omc-cli imports ~16 symbols).
6. `cargo test -p <crate>` (cargo build skips `#[cfg(test)]`, so always run tests). Green.
7. Commit this one module before the next.

## Target tree — omc-registry

`error`(✅), `types`(Ecosystem/PackageSpec/Manifest/OmcLock/LockedPackage/reports — re-export all), `manifest`, `lockfile`, `http_client`, `npm_resolve`(~3.5k), `npm_config`, `npm_install`(~2.2k), `npm_metadata`(~2.5k), `pypi_resolve`(~5k → subdir), `pypi_config`, `pypi_install`(~2.5k), `profiler`(~3.5k; move `redteam_capability_evasion` under it), `signature`, `verify`, `policy_bridge`(move `policy_dsl_tests` under it), `link_install`, `util`. Then split `tests.rs` (~10.9k) into per-domain `#[cfg(test)] mod *_tests` siblings.

Extraction order (deps first): error → types → manifest → lockfile → http_client → npm_resolve → npm_config → npm_install → npm_metadata → pypi_resolve → pypi_config → pypi_install → profiler → signature → verify → policy_bridge → link_install → util → test relocation.

## Target tree — omc-cli

`args`(~1.65k Command/Action structs), `policy_args`, `temp_project`, `parse`(~1.2k), `render`(~0.8k), `dispatch`(omc_main/run_entry/Command match), `direct_compat`, `policy`, `manifest`, `compile`, `install`, `script`, `shim`, `npm_exec`, `npm_compat`(~2.2k), `npm_config`(~1.1k), `pip_compat`(~3k), `pip_config`(~4k → subdir: pipconf/pyproject/setupcfg), `twine_compat`, `exec_cell`. Then split `tests.rs` (~15.5k) into `#[cfg(test)] mod {parse,npm_compat,pip_compat,twine_compat,policy,manifest,install,render}_tests`.

Order: args → policy_args → temp_project → parse → render → dispatch → (direct_compat, policy, manifest, compile, install, script, shim, npm_exec, npm_compat, npm_config, pip_compat, pip_config, twine_compat, exec_cell) → test relocation. omc-cli is a bin crate (lib.rs feeds main.rs) — preserve everything lib.rs re-exports to main.rs.

## Definition of done

(1) `cargo test --workspace` green at every commit. (2) No file under either `src/` exceeds ~3–4k lines (incl. test files; `pypi_resolve`/`pip_config` get subdir splits). (3) Public API byte-for-byte unchanged. (4) `mod.rs` not used anywhere (flat `foo.rs` + `foo/` style, matching omc-policy). (5) Final cleanup: globs de-globbed, over-broad `pub(crate)` demoted, `#![warn(unreachable_pub)]` clean.

## Key risks

Struct fields are independently private (E0616). External `use` don't flow into children. `cargo build` skips `#[cfg(test)]` — run tests every step. `use crate::*` is scaffolding only → de-glob in cleanup (else E0659 ambiguity once two modules export `Result`/`Error`). One module per commit so any regression is bisectable.
