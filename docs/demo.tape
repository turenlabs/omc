# OMC README demo — render with:  vhs docs/demo.tape
# Produces docs/demo.gif. Requires `omc` on PATH (brew install turenlabs/tap/omc).
Output docs/demo.gif

Require omc

Set Shell "bash"
Set FontSize 14
Set Width 1180
Set Height 940
Set Padding 22
Set TypingSpeed 45ms
Set Theme "Dracula"

# --- setup (hidden): isolated throwaway project + a clean prompt ---
Hide
Type "cd $(mktemp -d)" Enter
Type `PS1='\[\e[1;36m\]❯\[\e[0m\] '` Enter
Type "clear" Enter
Show

Sleep 600ms

# 1. Start a deny-by-default project
Type "# a drop-in npm/pip — packages can't touch your machine unless you allow it" Sleep 400ms Enter
Type "omc init --name demo" Sleep 250ms Enter
Sleep 1.2s

# 2. A pure package installs frictionlessly — zero host access, no scripts run
Type "# safe packages just install — no install scripts, no host access" Sleep 400ms Enter
Type "omc add --npm is-odd@3.0.1" Sleep 250ms Enter
Sleep 2.2s

# 3. Preview a risky package BEFORE installing (read-only) — OMC blocks it
Type "# now preview a risky one, read-only, before it ever runs" Sleep 400ms Enter
Type "omc inspect --npm esbuild@0.19.12" Sleep 250ms Enter
Sleep 5s
