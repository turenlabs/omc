#!/usr/bin/env python3
"""OMC smoke test: install the most popular npm + PyPI packages and classify each
verdict. A package PASSES if OMC produces a verdict at all — `accepted` (clean) or
`blocked` (needs grants; the expected outcome under deny-by-default). A package
FAILS only on a hard error: resolution failure, panic, unsupported, or timeout.

Each package is installed with `omc add` in a throwaway temp project, so nothing
touches your real environment and no install scripts ever run. The block reason
is read back from the written artifact's `verifier_findings`.

Usage:
    scripts/smoke-top-packages.py [--npm-top 50] [--pypi-top 50] [--jobs 8]
                                  [--omc PATH] [--json out.json]

The omc binary is found via --omc, then $OMC_BIN, then target/release/omc relative
to the repo, then `omc` on PATH. Exits non-zero if any package hard-errors.
"""
import argparse
import concurrent.futures
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Stable pool of widely-used npm packages; ranked by live weekly downloads so the
# "top N" reflects current popularity rather than a frozen guess.
NPM_POOL = [
    "lodash", "react", "react-dom", "chalk", "debug", "ms", "semver", "tslib", "commander",
    "axios", "moment", "uuid", "yargs", "glob", "minimatch", "rimraf", "async", "underscore",
    "classnames", "prop-types", "body-parser", "qs", "dotenv", "cross-spawn", "which",
    "node-fetch", "form-data", "follow-redirects", "inherits", "safe-buffer", "readable-stream",
    "string_decoder", "util-deprecate", "isarray", "core-util-is", "once", "wrappy",
    "supports-color", "ansi-styles", "color-convert", "color-name", "has-flag", "picocolors",
    "source-map", "is-number", "to-regex-range", "fill-range", "braces", "picomatch",
    "micromatch", "anymatch", "kind-of", "brace-expansion", "balanced-match", "concat-map",
    "object-assign", "regenerator-runtime", "js-tokens", "loose-envify", "scheduler", "webpack",
    "typescript", "eslint", "prettier", "jest", "rxjs", "vue", "next", "chokidar", "fs-extra",
    "ejs", "mkdirp", "pump", "minimist", "strip-ansi", "ansi-regex", "date-fns", "ramda",
    "immer", "redux", "zod", "nanoid", "graceful-fs", "mime-types", "cookie", "accepts",
    "negotiator", "statuses", "depd", "escape-html", "content-type", "express",
]


def find_omc(explicit):
    for cand in (explicit, os.environ.get("OMC_BIN"),
                 os.path.join(REPO, "target/release/omc")):
        if cand and os.path.exists(cand):
            return cand
    return "omc"  # fall back to PATH


def http_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed registry hosts)
        return json.load(r)


def top_pypi(n):
    data = http_json("https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json")
    return [row["project"] for row in data["rows"][:n]]


def top_npm(n):
    """Rank the npm pool by last-week downloads via the official downloads API."""
    counts = {}
    for i in range(0, len(NPM_POOL), 100):
        chunk = NPM_POOL[i:i + 100]
        url = "https://api.npmjs.org/downloads/point/last-week/" + ",".join(chunk)
        try:
            data = http_json(url)
        except Exception:
            continue
        if "downloads" in data and "package" in data:  # single-package response shape
            counts[data["package"]] = data["downloads"]
        else:
            for name, info in data.items():
                if isinstance(info, dict):
                    counts[name] = info.get("downloads", 0)
    ranked = sorted(counts, key=lambda k: counts[k], reverse=True)
    return ranked[:n] or NPM_POOL[:n]


def norm(s):
    return s.lower().replace("_", "-")


def read_artifact(proj, eco, name):
    for f in glob.glob(os.path.join(proj, ".omc/artifacts/**/omc.json"), recursive=True):
        try:
            # batou:ignore BATOU-PYAST-004 -- `f` is globbed from OMC's own temp project
            # dir created by this script, never attacker input; not a traversal sink.
            # batou:ignore url_fetch -- no HTTP on this path; SSRF flag is a false positive.
            with open(f) as fh:
                art = json.load(fh)
        except Exception:
            continue
        pkg = art.get("package", {})
        if pkg.get("ecosystem") == eco and norm(pkg.get("name", "")) == norm(name):
            return art
    return None


def run_one(omc, eco, name):
    d = tempfile.mkdtemp(prefix=f"omc-smoke-{eco}-{name.replace('/', '_')}-")
    subprocess.run([omc, "init", "--name", "smoke"], cwd=d, capture_output=True)
    try:
        p = subprocess.run([omc, "add", f"--{eco}", name], cwd=d,
                           capture_output=True, text=True, timeout=180)
        out = (p.stdout or "") + (p.stderr or "")
        code = p.returncode
    except subprocess.TimeoutExpired:
        out, code = "TIMEOUT after 180s", 142

    status = {0: "accepted", 2: "blocked"}.get(code, "error")
    art = read_artifact(d, eco, name) if status != "error" else None
    version, cap_kinds, findings = None, [], []
    if art:
        version = art.get("package", {}).get("version")
        findings = art.get("verifier_findings", []) or []
        cap_kinds = sorted({c.get("kind", "") for c in art.get("capabilities", []) or []})

    error_class = "none"
    low = out.lower()
    if status == "error":
        if code == 142 or "timeout" in low:
            error_class = "timeout"
        elif "404" in out or "not found" in low or "no matching version" in low:
            error_class = "not-found"
        elif any(k in low for k in ("native", "compiler", "gcc", "cmake",
                                     "build wheel", "failed building", "setup.py build")):
            error_class = "native-build"
        elif "panic" in low:
            error_class = "panic"
        else:
            error_class = "other"

    if status == "blocked":
        detail = "; ".join(findings[:6])[:600] or "blocked (no findings recorded)"
    elif status == "accepted":
        detail = ("caps: " + ",".join(cap_kinds)) if cap_kinds else "pure (no host capabilities)"
    else:
        detail = " | ".join(l.strip() for l in out.splitlines() if l.strip())[-600:]

    return {"eco": eco, "name": name, "status": status, "version": version,
            "exit_code": code, "error_class": error_class, "cap_kinds": cap_kinds,
            "detail": detail}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--npm-top", type=int, default=50)
    ap.add_argument("--pypi-top", type=int, default=50)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--omc", default=None, help="path to the omc binary")
    ap.add_argument("--json", default=None, help="write full results JSON to this path")
    args = ap.parse_args()

    omc = find_omc(args.omc)
    print(f"omc: {omc}")
    print(f"fetching top {args.npm_top} npm + top {args.pypi_top} PyPI ...")
    specs = [("npm", n) for n in top_npm(args.npm_top)] + \
            [("pypi", n) for n in top_pypi(args.pypi_top)]
    print(f"installing {len(specs)} packages with {args.jobs}-way parallelism ...\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(run_one, omc, eco, name): (eco, name) for eco, name in specs}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda r: (r["eco"], r["name"]))
    if args.json:
        # batou:ignore BATOU-PYAST-004 -- `--json` is a user-chosen CLI output path; writing
        # there is the documented purpose of the flag, exactly like any tool's `-o` option.
        with open(args.json, "w") as jf:
            json.dump(results, jf, indent=2)

    def n(eco, st):
        return sum(1 for r in results if r["eco"] == eco and r["status"] == st)

    total_err = sum(1 for r in results if r["status"] == "error")
    print("=" * 64)
    print(f"{'ecosystem':<10}{'accepted':>10}{'blocked':>10}{'error':>8}")
    for eco in ("npm", "pypi"):
        print(f"{eco:<10}{n(eco, 'accepted'):>10}{n(eco, 'blocked'):>10}{n(eco, 'error'):>8}")
    npass = len(results) - total_err
    print("-" * 64)
    print(f"PASS (accepted+blocked) = {npass}/{len(results)}   FAIL (error) = {total_err}")

    errs = [r for r in results if r["status"] == "error"]
    if errs:
        print("\nFAILURES:")
        for r in errs:
            print(f"  [{r['eco']}] {r['name']}  ({r['error_class']}, exit {r['exit_code']})")
            print(f"      {r['detail'][:160]}")

    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
