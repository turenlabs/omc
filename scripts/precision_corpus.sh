#!/usr/bin/env bash
# Precision-measurement corpus: resolve ~50 popular packages (biased to
# heavy/compiled PyPI wheels most prone to install-gate over-blocking) through
# the read-only `add_package_graph` path and capture every package's verdict +
# full per-finding detail as one JSON object per line.
#
# Read-only: no install scripts, isolated empty OMC_HOME, scratch project dir.
# Usage: scripts/precision_corpus.sh [output.jsonl]
set -u

BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/examples/corpus_capture"
OUT="${1:-/tmp/omc-precision/corpus.jsonl}"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

# Isolated empty OMC_HOME so the cache starts clean and global policy is empty.
OMC_HOME="$(mktemp -d /tmp/omc-home.XXXXXX)"
export OMC_HOME

PKGS=(
  # Heavy / compiled PyPI (most over-blocked)
  pypi:numpy pypi:pandas pypi:scipy pypi:cryptography pypi:cffi
  pypi:pycparser pypi:pillow pypi:matplotlib pypi:lxml pypi:pydantic
  pypi:pydantic-core pypi:aiohttp pypi:frozenlist pypi:multidict pypi:yarl
  pypi:greenlet pypi:sqlalchemy pypi:msgpack pypi:regex pypi:markupsafe
  pypi:jinja2 pypi:pyyaml pypi:wrapt pypi:coverage pypi:psutil
  pypi:orjson pypi:grpcio pypi:protobuf pypi:bcrypt pypi:charset-normalizer
  pypi:urllib3 pypi:requests pypi:click pypi:rich pypi:packaging
  pypi:attrs pypi:typing-extensions pypi:boto3 pypi:botocore
  # Heavy npm
  npm:esbuild npm:typescript npm:webpack
)

echo "OMC_HOME=$OMC_HOME" >&2
echo "packages: ${#PKGS[@]}" >&2

for p in "${PKGS[@]}"; do
  echo "==> $p" >&2
  "$BIN" "$p" >> "$OUT" 2>>"${OUT%.jsonl}.err"
done

rm -rf "$OMC_HOME"
echo "done -> $OUT ($(wc -l < "$OUT") lines)" >&2
