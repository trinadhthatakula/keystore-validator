#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${1:-"$ROOT/engine/jks/dist"}
mkdir -p "$OUTPUT"
OUTPUT=$(CDPATH= cd -- "$OUTPUT" && pwd)
(cd "$ROOT/engine/jks" && GOOS=js GOARCH=wasm go build -trimpath -o "$OUTPUT/jks.wasm" .)
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUTPUT/wasm_exec.js"
