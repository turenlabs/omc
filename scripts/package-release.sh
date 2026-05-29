#!/usr/bin/env bash
# Package OMC release binaries into a distributable tarball + checksum.
#
# Usage: scripts/package-release.sh <version> <target-triple> [bin-dir]
#
# Layout inside the tarball (omc-<version>-<target>/):
#   omc            the package-manager binary (put this on PATH)
#   shims/         drop-in node/npm/npx/pip/pip3/python/python3/twine that route
#                  through OMC; OPT-IN — adding them to PATH shadows the system
#                  tools, so they ship in a subdirectory rather than next to omc.
#   README.md, LICENSE (when present)
set -euo pipefail

VERSION="${1:?usage: package-release.sh <version> <target> [bin-dir]}"
TARGET="${2:?usage: package-release.sh <version> <target> [bin-dir]}"
BIN_DIR="${3:-target/${TARGET}/release}"

# Fall back to the plain release dir when not built with an explicit --target.
if [ ! -x "${BIN_DIR}/omc" ]; then
  BIN_DIR="target/release"
fi
if [ ! -x "${BIN_DIR}/omc" ]; then
  echo "error: could not find a built omc binary in ${BIN_DIR}" >&2
  exit 1
fi

SHIMS=(npm npx node pip pip3 python python3 twine)
STAGE="omc-${VERSION}-${TARGET}"
OUT="dist/${STAGE}"

rm -rf "${OUT}"
mkdir -p "${OUT}/shims"

install -m 0755 "${BIN_DIR}/omc" "${OUT}/omc"
for shim in "${SHIMS[@]}"; do
  install -m 0755 "${BIN_DIR}/${shim}" "${OUT}/shims/${shim}"
done

for extra in README.md LICENSE LICENSE.txt LICENSE-APACHE; do
  [ -f "${extra}" ] && cp "${extra}" "${OUT}/" || true
done

cat > "${OUT}/INSTALL.txt" <<EOF
OMC ${VERSION} (${TARGET})

Put 'omc' on your PATH:
  install -m 0755 omc /usr/local/bin/omc

The shims/ directory holds drop-in node/npm/npx/pip/pip3/python/python3/twine
that route through OMC's deny-by-default runtime. They are OPT-IN because adding
them to PATH shadows the system tools:
  export PATH="\$PWD/shims:\$PATH"

Default policy denies reading sensitive files (.ssh, .env, keys, tokens, cloud
credentials) even under broad grants; override per-file with fs.read:<path> or
globally with --allow-sensitive.
EOF

tar -czf "dist/${STAGE}.tar.gz" -C dist "${STAGE}"

# Also publish the bare `omc` binary as a standalone single-file download
# (no shims), named by target so all platforms coexist in one release.
SOLO="omc-${TARGET}"
install -m 0755 "${BIN_DIR}/omc" "dist/${SOLO}"

# Checksums (prefer sha256sum, fall back to shasum on macOS runners).
checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" > "$1.sha256"
  else
    shasum -a 256 "$1" > "$1.sha256"
  fi
}
( cd dist && checksum "${STAGE}.tar.gz" && checksum "${SOLO}" )

# Keep only the distributable artifacts in dist/.
rm -rf "${OUT}"

echo "dist/${STAGE}.tar.gz"
echo "dist/${SOLO}"
cat "dist/${SOLO}.sha256"
