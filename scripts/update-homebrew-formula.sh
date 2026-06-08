#!/usr/bin/env bash
# Update the Homebrew tap formula for a new OMC release.
#
# Reads env:
#   VERSION             release version without the leading v (e.g. 0.1.0)
#   TAG                 release tag (e.g. v0.1.0)
#   HOMEBREW_TAP_TOKEN  PAT with write access to the tap repo (optional)
#   TAP_REPO            tap repo as owner/repo (e.g. turenlabs/homebrew-tap)
#   SRC_REPO            source repo as owner/repo (defaults to $GITHUB_REPOSITORY,
#                       then turenlabs/omc) — the tagged tarball is fetched from it
#
# The formula is a BINARY formula: it installs the prebuilt per-platform `omc`
# tarballs from the GitHub Release (no compile). This script fetches the release
# SHA256SUMS, rewrites each platform's url + sha256 (and the version) in
# Formula/omc.rb in place, and commits it to the tap.
# When HOMEBREW_TAP_TOKEN or TAP_REPO is absent it logs and exits 0 — a release
# must never fail just because the tap is not configured yet.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${TAG:?TAG is required}"

if [ -z "${HOMEBREW_TAP_TOKEN:-}" ] || [ -z "${TAP_REPO:-}" ]; then
  echo "HOMEBREW_TAP_TOKEN / TAP_REPO not set — skipping tap update."
  echo "Configure the HOMEBREW_TAP_REPO variable and HOMEBREW_TAP_TOKEN secret to enable it."
  exit 0
fi

SRC_REPO="${SRC_REPO:-${GITHUB_REPOSITORY:-turenlabs/omc}}"
SUMS_URL="https://github.com/${SRC_REPO}/releases/download/${TAG}/SHA256SUMS"
echo "Fetching release checksums: ${SUMS_URL}"
curl -fsSL "${SUMS_URL}" -o SHA256SUMS
cat SHA256SUMS

# Rewrite each platform's url + sha256 (and the version) in the binary formula.
python3 - "$VERSION" "$SRC_REPO" <<'PY'
import re, sys

version, src_repo = sys.argv[1], sys.argv[2]
# Platforms shipped as prebuilt release tarballs (must match release.yml's matrix
# and the on_macos/on_linux blocks in Formula/omc.rb).
targets = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
]

# Map each release asset name to its sha256 from SHA256SUMS.
sums = {}
for line in open("SHA256SUMS"):
    parts = line.split()
    if len(parts) == 2:
        sums[parts[1].lstrip("*")] = parts[0]

text = open("Formula/omc.rb").read()
text = re.sub(r'version "[^"]*"', f'version "{version}"', text, count=1)

for target in targets:
    asset = f"omc-{version}-{target}.tar.gz"
    sha = sums.get(asset)
    if not sha:
        raise SystemExit(f"missing sha256 for {asset} in SHA256SUMS")
    url = f"https://github.com/{src_repo}/releases/download/v{version}/{asset}"
    # Update this platform's url (matched by its unique target triple), then the
    # sha256 line immediately following it.
    text = re.sub(rf'url "[^"]*{re.escape(target)}\.tar\.gz"', f'url "{url}"', text, count=1)
    text = re.sub(
        rf'(url "{re.escape(url)}"\n\s*sha256 ")[0-9a-f]{{64}}(")',
        rf'\g<1>{sha}\g<2>',
        text,
        count=1,
    )

open("Formula/omc.rb", "w").write(text)
print(f"Formula updated to {version} (binary, {len(targets)} platforms)")
PY

# Keep the token OUT of any URL (it could leak in error output). The tap is a
# public repo, so clone over plain HTTPS, and authenticate the push with a
# short-lived Authorization header passed via `git -c http.extraheader` — the
# same mechanism actions/checkout uses. The token is never written to disk
# (.git/config) or echoed in a remote URL.
tmp="$(mktemp -d)"
git clone --depth 1 "https://github.com/${TAP_REPO}.git" "$tmp"
mkdir -p "$tmp/Formula"
cp Formula/omc.rb "$tmp/Formula/omc.rb"
cd "$tmp"
git config user.name "omc-release-bot"
git config user.email "omc-release-bot@users.noreply.github.com"
git add Formula/omc.rb
if git diff --cached --quiet; then
  echo "Formula already up to date."
else
  git commit -m "omc ${VERSION}"
  auth_header="AUTHORIZATION: basic $(printf 'x-access-token:%s' "${HOMEBREW_TAP_TOKEN}" | base64 | tr -d '\n')"
  git -c http.extraheader="${auth_header}" push origin HEAD
  echo "Pushed omc ${VERSION} formula to ${TAP_REPO}."
fi
