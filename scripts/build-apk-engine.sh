#!/bin/sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
output_path=${1:-"$root_dir/public/apk-engine.wasm"}
mkdir -p "$(dirname -- "$output_path")"
(cd "$root_dir/engine/apk" && GOOS=js GOARCH=wasm go build -trimpath -o "$output_path" .)
printf 'Built APK verifier: %s\n' "$output_path"
