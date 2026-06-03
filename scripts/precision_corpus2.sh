#!/usr/bin/env bash
# Precision-measurement corpus, ROUND 2: 100 packages NOT in
# scripts/precision_corpus.sh. Biased to npm this round (~55 npm / ~45 pypi)
# and to variety (CLI tools, web frameworks, build tools, parsers, ORMs, test
# libs) to surface remaining install-gate extraction false positives the
# first ~50 (pypi-heavy) corpus didn't reach.
#
# Same read-only capture path as round 1: resolve each spec through
# add_package_graph with record_blocked, isolated empty OMC_HOME, no install
# scripts, scratch project dir. One JSON object per line (JSONL).
# Usage: scripts/precision_corpus2.sh [output.jsonl]
set -u

BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/examples/corpus_capture"
OUT="${1:-/tmp/omc-precision2/corpus.jsonl}"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

# Isolated empty OMC_HOME so the cache starts clean and global policy is empty.
OMC_HOME="$(mktemp -d /tmp/omc-home2.XXXXXX)"
export OMC_HOME

PKGS=(
  # ---- npm (~55): CLI tools, web frameworks, build tools, parsers, test libs ----
  npm:react npm:react-dom npm:vue npm:express npm:koa
  npm:fastify npm:next npm:axios npm:lodash npm:chalk
  npm:commander npm:yargs npm:inquirer npm:ora npm:debug
  npm:rxjs npm:moment npm:dayjs npm:uuid npm:nanoid
  npm:dotenv npm:cors npm:body-parser npm:morgan npm:helmet
  npm:ws npm:socket.io npm:node-fetch npm:got npm:cross-env
  npm:rimraf npm:glob npm:fs-extra npm:chokidar npm:execa
  npm:semver npm:eslint npm:prettier npm:jest npm:mocha
  npm:chai npm:vitest npm:rollup npm:vite npm:postcss
  npm:tailwindcss npm:babel-core npm:@babel/core npm:zod npm:joi
  npm:prisma npm:sequelize npm:mongoose npm:knex npm:pg

  # ---- pypi (~45): web frameworks, ORMs, CLI, parsers, test libs ----
  pypi:flask pypi:django pypi:fastapi pypi:starlette pypi:uvicorn
  pypi:gunicorn pypi:werkzeug pypi:httpx pypi:certifi pypi:idna
  pypi:six pypi:python-dateutil pypi:pytz pypi:tomli pypi:tomlkit
  pypi:rich-click pypi:typer pypi:tqdm pypi:colorama pypi:tabulate
  pypi:pytest pypi:pytest-cov pypi:tox pypi:nox pypi:hypothesis
  pypi:mock pypi:freezegun pypi:faker pypi:factory-boy pypi:responses
  pypi:beautifulsoup4 pypi:soupsieve pypi:html5lib pypi:markdown pypi:docutils
  pypi:pygments pypi:jsonschema pypi:marshmallow pypi:alembic pypi:redis
  pypi:celery pypi:kombu pypi:billiard pypi:vine pypi:dnspython
)

echo "OMC_HOME=$OMC_HOME" >&2
echo "packages: ${#PKGS[@]}" >&2

for p in "${PKGS[@]}"; do
  echo "==> $p" >&2
  "$BIN" "$p" >> "$OUT" 2>>"${OUT%.jsonl}.err"
done

rm -rf "$OMC_HOME"
echo "done -> $OUT ($(wc -l < "$OUT") lines)" >&2
