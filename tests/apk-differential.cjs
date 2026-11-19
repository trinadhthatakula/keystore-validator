/* Runs the browser WASM engine with Node's equivalent FileReaderSync API. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { webcrypto } = require('node:crypto');

globalThis.crypto ??= webcrypto;
const [assetsDir, fixtureDir, apksigner, expectedDigest, expectedSha1] = process.argv.slice(2);
if (!assetsDir || !fixtureDir || !apksigner || !expectedDigest || !expectedSha1) {
  throw new Error('Usage: apk-differential.cjs ASSETS_DIR FIXTURE_DIR APKSIGNER EXPECTED_SHA256 EXPECTED_SHA1');
}
require(path.join(assetsDir, 'wasm_exec.js'));

let maxRead = 0;
class TestFile {
  constructor(filePath) {
    this.fd = fs.openSync(filePath, 'r');
    this.size = fs.fstatSync(this.fd).size;
  }
  slice(start, end) { return { fd: this.fd, start, length: end - start }; }
  close() { fs.closeSync(this.fd); }
}
globalThis.FileReaderSync = class {
  readAsArrayBuffer(slice) {
    maxRead = Math.max(maxRead, slice.length);
    const bytes = new Uint8Array(slice.length);
    const n = fs.readSync(slice.fd, bytes, 0, bytes.length, slice.start);
    assert.equal(n, bytes.length, 'fixture read was truncated');
    return bytes.buffer;
  }
};

async function main() {
  const go = new Go();
  const wasm = fs.readFileSync(path.join(assetsDir, 'apk-engine.wasm'));
  const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
  void go.run(instance);
  assert.equal(typeof globalThis.keystoreVerifyApk, 'function');

  const cases = [
    { name: 'v2.apk', reference: true, expected: true },
    { name: 'v2v3.apk', reference: true, expected: true },
    { name: 'tampered.apk', reference: false, expected: false },
    { name: 'unsigned.apk', reference: false, expected: false },
    { name: 'v1.apk', reference: true, expected: false, unsupported: 'v1-only' },
  ];
  if (fs.existsSync(path.join(fixtureDir, 'large.apk'))) {
    assert.ok(fs.statSync(path.join(fixtureDir, 'large.apk')).size >= 100 * 1024 * 1024, 'large fixture must exceed 100 MiB');
    cases.push({ name: 'large.apk', reference: true, expected: true });
  }
  for (const item of cases) {
    const fixture = path.join(fixtureDir, item.name);
    const reference = spawnSync(apksigner, ['verify', '--verbose', '--print-certs', '--min-sdk-version', '24', '--max-sdk-version', '35', fixture], { encoding: 'utf8' });
    if (reference.error) throw reference.error;
    assert.equal(reference.status === 0, item.reference, `${item.name}: unexpected apksigner exit ${reference.status}: ${reference.stdout} ${reference.stderr}`);
    const file = new TestFile(fixture);
    let result;
    try { result = globalThis.keystoreVerifyApk(file); } finally { file.close(); }
    assert.equal(result.verified, item.expected, `${item.name}: ${JSON.stringify(result)}`);
    // Compare fingerprints even when the engine deliberately refuses to
    // verify a v1-only signature: its certificate is diagnostic only.
    if (item.reference) {
      const match = reference.stdout.match(/certificate SHA-256 digest:\s*([0-9a-f:]+)/i);
      assert.ok(match, `${item.name}: missing reference fingerprint`);
      const official = match[1].replaceAll(':', '').toLowerCase();
      assert.equal(official, expectedDigest.toLowerCase(), `${item.name}: keytool and apksigner disagree`);
      const sha1Match = reference.stdout.match(/certificate SHA-1 digest:\s*([0-9a-f:]+)/i);
      assert.ok(sha1Match, `${item.name}: missing reference SHA-1 fingerprint`);
      const officialSha1 = sha1Match[1].replaceAll(':', '').toLowerCase();
      assert.equal(officialSha1, expectedSha1.toLowerCase(), `${item.name}: SHA-1 differs from keytool`);
      assert.equal(result.signers.length, 1, `${item.name}: unexpected signer count`);
      assert.equal(result.signers[0].sha256.replaceAll(':', '').toLowerCase(), official, `${item.name}: signer differs from apksigner`);
      assert.equal(result.signers[0].sha1.replaceAll(':', '').toLowerCase(), officialSha1, `${item.name}: SHA-1 signer differs from apksigner`);
    }
    if (item.unsupported) assert.match(result.errors.join(' '), new RegExp(item.unsupported, 'i'));
    if (!item.expected) assert.ok(result.errors.length, `${item.name}: expected a clear failure`);
    console.log(`${item.name}: apksigner=${item.reference ? 'valid' : 'invalid'}; browser engine=${item.expected ? 'verified' : 'unverified'}${item.unsupported ? ' (unsupported)' : ''}`);
  }
  if (fs.existsSync(path.join(fixtureDir, 'large.apk'))) {
    assert.ok(maxRead <= 1024 * 1024, `unexpected read size for the large fixture: ${maxRead}`);
  }
  console.log(`Largest fixture read: ${maxRead} bytes`);
}
main().then(() => process.exit(0), error => { console.error(error); process.exit(1); });
