#!/usr/bin/env bash
# Update the Homebrew tap formula for a new OMC release.
#
# Reads env:
#   VERSION             release version without the leading v (e.g. 0.1.0)
#   TAG                 release tag (e.g. v0.1.0)
#   HOMEBREW_TAP_TOKEN  PAT with write access to the tap repo (optional)
#   TAP_REPO            tap repo as owner/repo (e.g. turenio/homebrew-tap)
#
# It computes the sha256 of the tagged source tarball, regenerates the formula
# from Formula/omc.rb with the new url/sha256/version, and commits it to the tap.
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

SRC_URL="https://github.com/turenio/omc/archive/refs/tags/${TAG}.tar.gz"
echo "Fetching source tarball: ${SRC_URL}"
curl -fsSL "${SRC_URL}" -o source.tar.gz
SHA256="$(sha256sum source.tar.gz | awk '{print $1}')"
echo "sha256=${SHA256}"

# Regenerate the formula's stable stanza in place.
python3 - "$VERSION" "$SRC_URL" "$SHA256" <<'PY'
import re, sys
version, url, sha = sys.argv[1], sys.argv[2], sys.argv[3]
text = open("Formula/omc.rb").read()
text = re.sub(r'url ".*?"', f'url "{url}"', text, count=1)
text = re.sub(r'sha256 "[0-9a-f]{64}"', f'sha256 "{sha}"', text, count=1)
text = re.sub(r'version ".*?"', f'version "{version}"', text, count=1)
open("Formula/omc.rb", "w").write(text)
print(f"Formula updated to {version}")
PY

tmp="$(mktemp -d)"
git clone "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${TAP_REPO}.git" "$tmp"
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
  git push origin HEAD
  echo "Pushed omc ${VERSION} formula to ${TAP_REPO}."
fi
