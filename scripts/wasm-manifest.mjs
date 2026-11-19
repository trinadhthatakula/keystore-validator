import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const roots = ['engine/jks', 'engine/apk'];
const buildScripts = ['scripts/build-jks-engine.sh', 'scripts/build-apk-engine.sh'];
const assets = ['public/jks.wasm', 'public/apk-engine.wasm', 'public/wasm_exec.js'];
const manifestPath = 'public/wasm-manifest.json';

function sources(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return ['dist', 'tests'].includes(entry.name) ? [] : sources(path);
    if (!entry.isFile() || entry.name.endsWith('_test.go')) return [];
    return entry.name.endsWith('.go') || entry.name === 'go.mod' || entry.name === 'go.sum' ? [path] : [];
  });
}
function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
function sourceHash() {
  const hash = createHash('sha256');
  for (const path of [...roots.flatMap(sources), ...buildScripts].sort()) {
    hash.update(path).update('\0').update(readFileSync(path));
  }
  return hash.digest('hex');
}
try {
  if (process.argv[2] === 'write') {
    const manifest = {
      sourceSha256: sourceHash(),
      goVersion: execFileSync('go', ['version'], { encoding: 'utf8' }).trim(),
      assets: Object.fromEntries(assets.map((path) => [path, digest(path)])),
    };
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    console.log('Recorded the bundled WASM asset checksums.');
  } else if (process.argv[2] === 'check') {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (manifest.sourceSha256 !== sourceHash()) throw new Error('WASM sources changed since the assets were built.');
    for (const path of assets) if (manifest.assets?.[path] !== digest(path)) throw new Error(`Checksum mismatch: ${path}`);
    console.log('Bundled WASM assets match their source manifest.');
  } else {
    throw new Error('Use write or check.');
  }
} catch (error) {
  console.error(`WASM asset check failed: ${error.message} Run npm run build:wasm with Go installed.`);
  process.exitCode = 1;
}
