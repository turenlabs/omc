# OMC

**A drop-in `npm`/`pip` that never runs install scripts and won't let packages touch your secrets.**

Packages don't execute as JavaScript or Python when you install them. OMC resolves them, compiles their code to a small **verified bytecode**, and denies anything dangerous **by default** — reading env vars, files, the network, spawning processes. Reading sensitive files (`~/.ssh`, `.env`, keys, tokens) stays blocked *even with* `--allow-all-host`. Access is granted explicitly, per package, and recorded.

```bash
brew tap turenio/omc https://github.com/turenio/omc && brew install omc

omc init --name myapp                  # new project
omc add --npm left-pad@1.3.0           # resolve + verify — no install scripts run
omc install                            # or: install straight from package.json / requirements.txt
```

A package that wants host access is **blocked** until you allow it:

```bash
omc add --npm esbuild@0.19.12                       # ✗ blocked (postinstall + network)
omc add --npm esbuild@0.19.12 --allow http:registry.npmjs.org   # ✓ allowed + recorded
```

That's the whole idea: **dependencies are behavior-typed artifacts, not trusted code.**

---

- 📖 **[Quickstart & full reference →](docs/REFERENCE.md)**
- 🏗️ Architecture: [docs/oss-microcode-runtime.md](docs/oss-microcode-runtime.md)
- 📦 Releasing: [docs/RELEASING.md](docs/RELEASING.md)

> Private repo: `brew install` and release downloads need `export HOMEBREW_GITHUB_API_TOKEN=…` (or `gh release download`).
