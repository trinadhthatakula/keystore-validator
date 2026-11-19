#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kv-jks-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
STORE_PASSWORD='café🔑pass'
keytool -genkeypair -alias alpha -keyalg RSA -keysize 2048 -dname CN=Alpha -validity 30 -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -keypass keypass1 -noprompt >/dev/null 2>&1
keytool -genkeypair -alias 'café-😀' -keyalg RSA -keysize 2048 -dname CN=Unicode -validity 30 -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -keypass keypass2 -noprompt >/dev/null 2>&1
keytool -exportcert -alias alpha -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/alpha.der" >/dev/null 2>&1
keytool -exportcert -alias 'café-😀' -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/unicode.der" >/dev/null 2>&1
keytool -importcert -alias trusted -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/alpha.der" -noprompt >/dev/null 2>&1
java --source 17 "$ROOT/engine/jks/tests/FixtureFormats.java" "$TEST_DIR/multiple.jks" "$TEST_DIR/modern.p12" "$TEST_DIR/private.pk8" "$TEST_DIR/empty.p12"
java -Dkeystore.pkcs12.legacy --source 17 "$ROOT/engine/jks/tests/FixtureFormats.java" "$TEST_DIR/multiple.jks" "$TEST_DIR/legacy.p12"
keytool -genkeypair -alias jce -keyalg RSA -keysize 2048 -dname CN=JCEKS -validity 30 -keystore "$TEST_DIR/store.jceks" -storetype JCEKS -storepass "$STORE_PASSWORD" -keypass keypass3 -noprompt >/dev/null 2>&1
keytool -exportcert -alias jce -keystore "$TEST_DIR/store.jceks" -storetype JCEKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/jce.der" >/dev/null 2>&1
keytool -importcert -alias trusted -keystore "$TEST_DIR/store.jceks" -storetype JCEKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/alpha.der" -noprompt >/dev/null 2>&1
cp "$TEST_DIR/store.jceks" "$TEST_DIR/secret.jceks"
keytool -genseckey -alias secret -keyalg AES -keysize 128 -keystore "$TEST_DIR/secret.jceks" -storetype JCEKS -storepass "$STORE_PASSWORD" -keypass keypass4 -noprompt >/dev/null 2>&1
keytool -exportcert -rfc -alias alpha -keystore "$TEST_DIR/multiple.jks" -storetype JKS -storepass "$STORE_PASSWORD" -file "$TEST_DIR/alpha.pem" >/dev/null 2>&1
if command -v openssl >/dev/null 2>&1; then
    openssl pkcs8 -inform DER -in "$TEST_DIR/private.pk8" -nocrypt -out "$TEST_DIR/private.pem" >/dev/null 2>&1
    openssl pkcs12 -export -inkey "$TEST_DIR/private.pem" -in "$TEST_DIR/alpha.pem" -name openssl -passout pass:testing123 -out "$TEST_DIR/openssl.p12" >/dev/null 2>&1
fi
java --source 17 "$ROOT/engine/jks/tests/EmptyStore.java" "$TEST_DIR/alpha.der" "$TEST_DIR/empty.jks"
(cd "$ROOT/engine/jks" && go test ./...)
(cd "$ROOT/engine/jks/pkcs12" && go test ./...)
"$ROOT/scripts/build-jks-engine.sh" "$TEST_DIR/assets"
node "$ROOT/engine/jks/tests/check.cjs" "$TEST_DIR"
