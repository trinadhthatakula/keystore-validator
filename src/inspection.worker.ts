import type { ApkResult, InspectionRequest, InspectionResponse, KeystoreResult } from './types';

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
interface JksSuccess extends KeystoreResult { ok: true }
interface JksFailure { ok: false; error?: { message?: string } }
type EngineGlobal = typeof globalThis & {
  Go?: new () => GoRuntime;
  inspectJks?: (bytes: Uint8Array, password: string) => JksSuccess | JksFailure;
  keystoreVerifyApk?: (file: File) => ApkResult;
};

const engine = globalThis as EngineGlobal;
const post = (message: InspectionResponse): void => self.postMessage(message);
const assetUrl = (name: string): string => new URL(`${import.meta.env.BASE_URL}${name}`, self.location.origin).href;

async function startEngine(name: string): Promise<void> {
  // The runtime and binaries are bundled with this site; no files are uploaded.
  await import(/* @vite-ignore */ assetUrl('wasm_exec.js'));
  if (!engine.Go) throw new Error('The local inspector could not start in this browser.');
  const go = new engine.Go();
  const response = await fetch(assetUrl(name));
  if (!response.ok) throw new Error('The local inspector could not be loaded.');
  const binary = await response.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(binary, go.importObject);
  // Each inspection has its own worker, so this runtime is discarded on completion.
  void go.run(instance).catch(() => post({ type: 'error', message: 'The local inspector stopped unexpectedly.' }));
}

self.onmessage = async (event: MessageEvent<InspectionRequest>): Promise<void> => {
  const request = event.data;
  try {
    if (request.type === 'keystore') {
      if (request.file.size > 16 * 1024 * 1024) throw new Error('Keystores larger than 16 MiB are not supported.');
      post({ type: 'progress', message: 'Opening the keystore locally…' });
      await startEngine('jks.wasm');
      if (!engine.inspectJks) throw new Error('The local keystore inspector could not start.');
      const bytes = new Uint8Array(await request.file.arrayBuffer());
      let result: JksSuccess | JksFailure;
      try { result = engine.inspectJks(bytes, request.password); }
      finally { bytes.fill(0); request.password = ''; }
      if (!result.ok) throw new Error(result.error?.message || 'The keystore could not be inspected.');
      post({ type: 'keystore-result', result: { format: result.format, aliases: result.aliases, integrity: result.integrity } });
    } else if (request.type === 'apk') {
      post({ type: 'progress', message: 'Checking the APK signature locally…' });
      await startEngine('apk-engine.wasm');
      if (!engine.keystoreVerifyApk) throw new Error('The local APK inspector could not start.');
      post({ type: 'apk-result', result: engine.keystoreVerifyApk(request.file) });
    } else {
      throw new Error('Unknown inspection request.');
    }
  } catch (error) {
    post({ type: 'error', message: error instanceof Error ? error.message : 'Unable to inspect this file locally.' });
  }
};
