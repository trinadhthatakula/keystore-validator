#!/bin/sh
# Run ./tests/apk-differential.sh to compare the WASM engine with SDK tools.
# Requires Go, Node, Python, Java keytool and an Android SDK. Set ANDROID_SDK_ROOT
# or ANDROID_HOME if needed. Set KV_TEST_LARGE=1 to add a 100+ MiB APK fixture.
# The test creates disposable keys and files in a temporary directory.
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK_DIR=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-"$HOME/Library/Android/sdk"}}
if [ ! -d "$SDK_DIR" ] && [ -d "$HOME/Android/Sdk" ]; then SDK_DIR="$HOME/Android/Sdk"; fi
if [ ! -d "$SDK_DIR" ]; then
  printf '%s\n' 'Android SDK not found; set ANDROID_SDK_ROOT or ANDROID_HOME.' >&2
  exit 2
fi
for command in go node python3 keytool; do
  if ! command -v "$command" >/dev/null 2>&1; then printf 'Required tool not found: %s\n' "$command" >&2; exit 2; fi
done
# Select the highest installed stable build-tools version and Android platform.
TOOL_PATHS=$(python3 - "$SDK_DIR" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
def key(p): return tuple(int(x) for x in re.findall(r'\d+',p.name))
tools = [p for p in (root/'build-tools').glob('*') if 'rc' not in p.name.lower() and (p/'apksigner').is_file() and (p/'aapt2').is_file()]
platforms = [p for p in (root/'platforms').glob('android-*') if (p/'android.jar').is_file()]
if not tools or not platforms:
    print('Android SDK requires build-tools with apksigner/aapt2 and a platform android.jar.',file=sys.stderr)
    sys.exit(2)
print(max(tools,key=key))
print(max(platforms,key=key)/'android.jar')
PY
)
BUILD_DIR=$(printf '%s\n' "$TOOL_PATHS" | sed -n '1p')
PLATFORM_JAR=$(printf '%s\n' "$TOOL_PATHS" | sed -n '2p')
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kv-apk-differential.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
mkdir -p "$TEST_DIR/source-assets" "$TEST_DIR/wasm"
cat > "$TEST_DIR/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.validator.fixture" android:versionCode="1" android:versionName="1">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="29" />
  <application android:label="Validator test fixture" />
</manifest>
XML
printf '%s\n' 'Disposable signed payload for validator tests.' > "$TEST_DIR/source-assets/payload.txt"
"$BUILD_DIR/aapt2" link -I "$PLATFORM_JAR" --manifest "$TEST_DIR/AndroidManifest.xml" -A "$TEST_DIR/source-assets" -o "$TEST_DIR/unsigned.apk"
keytool -genkeypair -alias fixture -keyalg RSA -keysize 2048 -dname 'CN=Validator test fixture' -validity 30 -keystore "$TEST_DIR/signing.jks" -storetype JKS -storepass testpass123 -keypass testpass123 -noprompt >/dev/null 2>&1
keytool -exportcert -alias fixture -keystore "$TEST_DIR/signing.jks" -storetype JKS -storepass testpass123 -file "$TEST_DIR/cert.der" >/dev/null 2>&1
DIGEST=$(python3 - "$TEST_DIR/cert.der" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
SHA1_DIGEST=$(python3 - "$TEST_DIR/cert.der" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha1(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
for SCHEME in v1 v2 v2v3; do
  V1=false; V2=false; V3=false
  case "$SCHEME" in v1) V1=true;; v2) V2=true;; v2v3) V2=true; V3=true;; esac
  "$BUILD_DIR/apksigner" sign --ks "$TEST_DIR/signing.jks" --ks-key-alias fixture --ks-pass pass:testpass123 --key-pass pass:testpass123 --min-sdk-version 24 --max-sdk-version 35 --v1-signing-enabled "$V1" --v2-signing-enabled "$V2" --v3-signing-enabled "$V3" --v4-signing-enabled false --out "$TEST_DIR/$SCHEME.apk" "$TEST_DIR/unsigned.apk" >/dev/null 2>&1
done
python3 - "$TEST_DIR/v2v3.apk" "$TEST_DIR/tampered.apk" <<'PY'
import pathlib, struct, sys, zipfile
source, destination = map(pathlib.Path,sys.argv[1:])
data = bytearray(source.read_bytes())
with zipfile.ZipFile(source) as z:
    info = z.getinfo('assets/payload.txt')
    start = info.header_offset
    name_len, extra_len = struct.unpack_from('<HH', data, start+26)
    offset = start+30+name_len+extra_len
    if info.compress_size < 1: raise RuntimeError('fixture payload is empty')
    data[offset] ^= 1
destination.write_bytes(data)
PY
if [ "${KV_TEST_LARGE:-0}" = 1 ]; then
  python3 - "$TEST_DIR/source-assets/payload.bin" <<'PY'
import sys
with open(sys.argv[1], 'wb') as f:
    f.truncate(110 * 1024 * 1024)
PY
  "$BUILD_DIR/aapt2" link -0 bin -I "$PLATFORM_JAR" --manifest "$TEST_DIR/AndroidManifest.xml" -A "$TEST_DIR/source-assets" -o "$TEST_DIR/large-unsigned.apk"
  "$BUILD_DIR/apksigner" sign --ks "$TEST_DIR/signing.jks" --ks-key-alias fixture --ks-pass pass:testpass123 --key-pass pass:testpass123 --min-sdk-version 24 --max-sdk-version 35 --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false --out "$TEST_DIR/large.apk" "$TEST_DIR/large-unsigned.apk" >/dev/null 2>&1
fi
"$PROJECT_DIR/scripts/build-apk-engine.sh" "$TEST_DIR/wasm/apk-engine.wasm" >/dev/null
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$TEST_DIR/wasm/wasm_exec.js"
node "$PROJECT_DIR/tests/apk-differential.cjs" "$TEST_DIR/wasm" "$TEST_DIR" "$BUILD_DIR/apksigner" "$DIGEST" "$SHA1_DIGEST"
