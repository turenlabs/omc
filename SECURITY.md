# Security Policy

omc is a security tool. We take the integrity of its supply-chain defenses
seriously and welcome reports of vulnerabilities.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to <https://github.com/turenio/omc/security/advisories>
2. Click **Report a vulnerability**
3. Provide as much detail as you can: affected version, reproduction steps,
   and the impact you observed.

Using private advisories keeps the report confidential while we investigate and
prepare a fix. We aim to acknowledge new reports within a few business days.

Please do **not** include real secrets, credentials, or live exploit payloads
in a report. Use canary/placeholder values (e.g. `evil.invalid`) to demonstrate
behavior, mirroring how the test suite is written.

## Supported Versions

Security fixes are applied to the latest released minor version. Older versions
are not maintained; please upgrade to the most recent release before reporting,
and confirm the issue still reproduces there.

| Version | Supported |
| ------- | --------- |
| latest release (current minor) | yes |
| older releases | no |

## Scope — What omc Defends, and What It Does Not

omc is a **deny-by-default, install-time / inspect-time gate** for npm and PyPI
packages. Being precise about its threat model matters, because relying on it
for guarantees it does not make is itself a risk.

**What omc does:**

- Profiles packages to a set of capability findings before they are linked.
- Verifies those findings against a policy and produces an allow/deny verdict.
- **Never executes package install/lifecycle scripts.** Inspection is static.
- Runs a sound interprocedural-taint engine for the exec-cell path, and a
  lightweight text-scan profiler at install/inspect time.

**What omc does NOT do:**

- It is **not a runtime sandbox.** Once you choose to execute code that omc
  has linked, omc does not contain, intercept, or monitor that execution. Use
  OS-level sandboxing (containers, seccomp, VMs) for runtime isolation.
- It does not guarantee detection of every malicious package. The install-time
  text scan is a heuristic layer; a determined adversary may evade it. Treat a
  clean verdict as "no known capability findings," not "proven safe."
- It does not replace dependency review, registry-side scanning, or
  reproducible-build verification.

In-scope vulnerability reports include: a way to obtain a benign verdict for a
package that exercises a denied capability (a soundness gap in the gate), a way
to make omc execute package code during inspection, or a path-traversal /
injection bug in omc itself. Out-of-scope: the fact that omc does not sandbox
code you deliberately run after it has been linked.
