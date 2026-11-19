#!/bin/sh
# Test BKS with disposable data produced by Bouncy Castle's Java provider.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -z "${BKS_BCPROV_JAR:-}" ] || [ ! -f "$BKS_BCPROV_JAR" ]; then
  printf '%s\n' 'Set BKS_BCPROV_JAR to a local Bouncy Castle bcprov jar.' >&2
  exit 2
fi
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kv-bks-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
PROVIDER=org.bouncycastle.jce.provider.BouncyCastleProvider
keytool -genkeypair -alias alpha -keyalg RSA -keysize 2048 -dname CN=Alpha -validity 30 -keystore "$TEST_DIR/store.bks" -storetype BKS -storepass testpass123 -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -genkeypair -alias 'café-😀' -keyalg RSA -keysize 2048 -dname CN=Unicode -validity 30 -keystore "$TEST_DIR/store.bks" -storetype BKS -storepass testpass123 -keypass otherpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -exportcert -alias alpha -keystore "$TEST_DIR/store.bks" -storetype BKS -storepass testpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/alpha.der" >/dev/null 2>&1
keytool -exportcert -alias 'café-😀' -keystore "$TEST_DIR/store.bks" -storetype BKS -storepass testpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/unicode.der" >/dev/null 2>&1
keytool -importcert -alias trusted -keystore "$TEST_DIR/store.bks" -storetype BKS -storepass testpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/alpha.der" -noprompt >/dev/null 2>&1
keytool -genkeypair -alias unicode -keyalg RSA -keysize 2048 -dname CN=UnicodePassword -validity 30 -keystore "$TEST_DIR/unicode-pass.bks" -storetype BKS -storepass 'café🔑pass' -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -exportcert -alias unicode -keystore "$TEST_DIR/unicode-pass.bks" -storetype BKS -storepass 'café🔑pass' -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/unicode-pass.der" >/dev/null 2>&1
keytool -J-Dorg.bouncycastle.bks.enable_v1=true -genkeypair -alias old -keyalg RSA -keysize 2048 -dname CN=Old -validity 30 -keystore "$TEST_DIR/old.bks" -storetype BKS-V1 -storepass testpass123 -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -J-Dorg.bouncycastle.bks.enable_v1=true -exportcert -alias old -keystore "$TEST_DIR/old.bks" -storetype BKS-V1 -storepass testpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/old.der" >/dev/null 2>&1
keytool -genkeypair -alias uber -keyalg RSA -keysize 2048 -dname CN=Uber -validity 30 -keystore "$TEST_DIR/store.uber" -storetype UBER -storepass testpass123 -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -exportcert -alias uber -keystore "$TEST_DIR/store.uber" -storetype UBER -storepass testpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/uber.der" >/dev/null 2>&1
keytool -genkeypair -alias unicode -keyalg RSA -keysize 2048 -dname CN=UnicodeUber -validity 30 -keystore "$TEST_DIR/unicode.uber" -storetype UBER -storepass 'café🔑pass' -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -exportcert -alias unicode -keystore "$TEST_DIR/unicode.uber" -storetype UBER -storepass 'café🔑pass' -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/uber-unicode.der" >/dev/null 2>&1
keytool -genkeypair -alias fips -keyalg RSA -keysize 2048 -dname CN=Fips -validity 30 -keystore "$TEST_DIR/store.bcfks" -storetype BCFKS -storepass 'café🔑pass' -keypass keypass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -genkeypair -alias 'café-😀' -keyalg RSA -keysize 2048 -dname CN=FipsUnicode -validity 30 -keystore "$TEST_DIR/store.bcfks" -storetype BCFKS -storepass 'café🔑pass' -keypass otherpass123 -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -noprompt >/dev/null 2>&1
keytool -exportcert -alias fips -keystore "$TEST_DIR/store.bcfks" -storetype BCFKS -storepass 'café🔑pass' -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/fips.der" >/dev/null 2>&1
keytool -exportcert -alias 'café-😀' -keystore "$TEST_DIR/store.bcfks" -storetype BCFKS -storepass 'café🔑pass' -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/fips-unicode.der" >/dev/null 2>&1
keytool -importcert -alias trusted -keystore "$TEST_DIR/store.bcfks" -storetype BCFKS -storepass 'café🔑pass' -providerclass "$PROVIDER" -providerpath "$BKS_BCPROV_JAR" -file "$TEST_DIR/fips.der" -noprompt >/dev/null 2>&1
javac -cp "$BKS_BCPROV_JAR" -d "$TEST_DIR" "$ROOT/bks/EmptyBks.java" "$ROOT/bcfks/FixtureVariants.java"
java -cp "$BKS_BCPROV_JAR:$TEST_DIR" FixtureVariants "$TEST_DIR/store.bcfks" "$TEST_DIR/scrypt.bcfks" "$TEST_DIR/sha3.bcfks" "$TEST_DIR/empty.bcfks"
java -cp "$BKS_BCPROV_JAR:$TEST_DIR" EmptyBks "$TEST_DIR/alpha.der" "$TEST_DIR/empty.bks"
java -cp "$BKS_BCPROV_JAR:$TEST_DIR" EmptyBks "$TEST_DIR/alpha.der" "$TEST_DIR/empty.uber" UBER
(cd "$ROOT" && BKS_FIXTURE_DIR="$TEST_DIR" go test ./bks -v)
(cd "$ROOT" && BC_FIXTURE_DIR="$TEST_DIR" go test ./bcfks -v)
"$ROOT/../../scripts/build-jks-engine.sh" "$TEST_DIR/assets"
node "$ROOT/bks/check.cjs" "$TEST_DIR"
