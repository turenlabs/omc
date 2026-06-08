# OMC README demo — render with:  vhs docs/demo.tape
# Produces docs/demo.gif. Requires `omc` on PATH (brew install turenlabs/tap/omc).
Output docs/demo.gif

Require omc

Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 1000
Set Padding 22
Set TypingSpeed 40ms
Set Theme "Dracula"

# --- setup (hidden): isolated throwaway project + a clean prompt ---
Hide
Type "cd $(mktemp -d)" Enter
Type `PS1='\[\e[1;36m\]❯\[\e[0m\] '` Enter
Type "clear" Enter
Show

Sleep 600ms

# A drop-in npm + pip that never runs install scripts.
Type "omc init --name demo" Sleep 250ms Enter
Sleep 1s

# Safe packages just install — no scripts, no host access — npm AND pip.
Type "# safe deps install with zero host access — no install scripts run" Sleep 300ms Enter
Type "omc add --npm is-odd@3.0.1" Sleep 250ms Enter
Sleep 1.8s
Type "omc add --pypi idna==3.7" Sleep 250ms Enter
Sleep 2s

# The money shot: preview a risky package, read-only, before it ever runs.
Type "# now X-ray a risky one BEFORE installing — read-only" Sleep 300ms Enter
Type "omc inspect --npm esbuild@0.19.12" Sleep 250ms Enter
Sleep 5s

# You're in control: allow it explicitly, and the grant is recorded.
Type "# not a brick wall — allow it on purpose, and it's recorded" Sleep 300ms Enter
Type "omc add --npm esbuild@0.19.12 --allow-all-host" Sleep 250ms Enter
Sleep 2.5s

# Everything you allowed is auditable — a clean CI gate.
Type "# audit the whole tree — a CI gate that fails on anything unreviewed" Sleep 300ms Enter
Type "omc audit" Sleep 250ms Enter
Sleep 3.5s
