# OMC README demo — render with:  vhs docs/demo.tape
# Produces docs/demo.gif. Requires `omc` on PATH (brew install turenlabs/tap/omc).
Output docs/demo.gif

Require omc

Set Shell "bash"
Set FontSize 13
Set Width 1140
Set Height 760
Set Padding 20
Set TypingSpeed 30ms
Set Theme "Dracula"

# --- setup (hidden): isolated throwaway project + clean policy home + a clean prompt ---
# OMC_HOME is a fresh temp dir so the demo always shows default deny-by-default
# behavior, never the renderer's personal ~/.omc grants (e.g. a trusted esbuild).
Hide
Type "cd $(mktemp -d)" Enter
Type "export OMC_HOME=$(mktemp -d)" Enter
Type `PS1='\[\e[1;36m\]❯\[\e[0m\] '` Enter
Type "omc init --name demo >/dev/null" Enter
Type "clear" Enter
Show

Sleep 400ms

# Safe deps install instantly — no host access, no install scripts (npm + pip).
Type "omc add --npm is-odd@3.0.1" Sleep 150ms Enter
Sleep 1.3s
Type "omc add --pypi idna==3.7" Sleep 150ms Enter
Sleep 1.6s

# The punch: inspect a risky package, read-only, BEFORE it ever runs.
Type "# inspect a risky one before installing it:" Sleep 200ms Enter
Type "omc inspect --npm esbuild@0.19.12" Sleep 150ms Enter
Sleep 4.5s
