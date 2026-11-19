import './style.css';
import type { ApkResult, CertificateInfo, InspectionRequest, InspectionResponse, KeystoreAlias, KeystoreResult } from './types';

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing interface element: ${id}`);
  return element as T;
};

const ksFileInput = byId<HTMLInputElement>('keystore-file');
const apkFileInput = byId<HTMLInputElement>('apk-file');
const passwordInput = byId<HTMLInputElement>('store-password');
const passwordToggle = byId<HTMLButtonElement>('password-toggle');
const ksButton = byId<HTMLButtonElement>('keystore-submit');
const apkButton = byId<HTMLButtonElement>('apk-submit');
const ksCancel = byId<HTMLButtonElement>('keystore-cancel');
const apkCancel = byId<HTMLButtonElement>('apk-cancel');
const ksStatus = byId<HTMLParagraphElement>('keystore-status');
const apkStatus = byId<HTMLParagraphElement>('apk-status');
const ksResultArea = byId<HTMLDivElement>('keystore-result');
const apkResultArea = byId<HTMLDivElement>('apk-result');
const aliasSelect = byId<HTMLSelectElement>('alias-select');
const aliasDetails = byId<HTMLDivElement>('alias-details');
const apkResultContent = byId<HTMLDivElement>('apk-result-content');
const comparison = document.querySelector<HTMLElement>('.comparison')!;
const comparisonTitle = byId<HTMLHeadingElement>('comparison-title');
const comparisonMessage = byId<HTMLParagraphElement>('comparison-message');
const comparisonBadge = byId<HTMLSpanElement>('comparison-badge');

let keystoreFile: File | null = null;
let apkFile: File | null = null;
let keystore: KeystoreResult | null = null;
let apk: ApkResult | null = null;
let ksWorker: Worker | null = null;
let apkWorker: Worker | null = null;

type Job = 'keystore' | 'apk';

const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
};

const setStatus = (kind: Job, message: string, error = false): void => {
  const node = kind === 'keystore' ? ksStatus : apkStatus;
  node.textContent = message;
  node.classList.toggle('error', error);
};

const setBusy = (kind: Job, busy: boolean): void => {
  const button = kind === 'keystore' ? ksButton : apkButton;
  const cancel = kind === 'keystore' ? ksCancel : apkCancel;
  const file = kind === 'keystore' ? keystoreFile : apkFile;
  button.disabled = busy || !file;
  button.querySelector('span')!.textContent = busy ? 'Inspecting…' : kind === 'keystore' ? 'Inspect keystore' : 'Inspect APK';
  cancel.hidden = !busy;
  if (kind === 'keystore') {
    ksFileInput.disabled = busy;
    passwordInput.disabled = busy;
    passwordToggle.disabled = busy;
  } else {
    apkFileInput.disabled = busy;
  }
};

const terminate = (kind: Job): void => {
  const worker = kind === 'keystore' ? ksWorker : apkWorker;
  worker?.terminate();
  if (kind === 'keystore') ksWorker = null;
  else apkWorker = null;
  setBusy(kind, false);
};

const normaliseSha256 = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const compact = value.replace(/[\s:]/g, '');
  return /^[0-9a-f]{64}$/i.test(compact) ? compact.toUpperCase() : null;
};

const activeAlias = (): KeystoreAlias | undefined => keystore?.aliases.find((item) => item.alias === aliasSelect.value);

const setComparison = (title: string, message: string, badge: string, state?: 'match' | 'mismatch'): void => {
  comparison.classList.toggle('match', state === 'match');
  comparison.classList.toggle('mismatch', state === 'mismatch');
  comparisonTitle.textContent = title;
  comparisonMessage.textContent = message;
  comparisonBadge.textContent = badge;
};

const updateComparison = (): void => {
  const selected = activeAlias();
  if (!keystore && !apk) {
    setComparison('Ready when you are', 'Add a keystore and an APK to compare their signing certificates.', 'AWAITING FILES');
  } else if (!selected) {
    setComparison('One more step', 'Inspect a keystore and choose a certificate to compare with this APK.', 'AWAITING KEYSTORE');
  } else if (!apk) {
    setComparison('One more step', 'Inspect an APK to compare it with the selected keystore certificate.', 'AWAITING APK');
  } else if (apk.verified !== true) {
    setComparison('Comparison unavailable', 'The APK signature was not verified. A matching certificate cannot establish a verified match.', 'NOT VERIFIED');
  } else {
    const selectedHash = normaliseSha256(selected.sha256);
    const signerHashes = apk.signers.map((item) => normaliseSha256(item.sha256));
    if (!selectedHash || !signerHashes.length || signerHashes.some((hash) => hash === null)) {
      setComparison('Comparison unavailable', 'A verified SHA-256 certificate fingerprint is missing or invalid.', 'CANNOT COMPARE');
      return;
    }
    const uniqueHashes = [...new Set(signerHashes)];
    const certificateOnly = selected.entryType === 'trusted-certificate' || selected.entryType === 'certificate';
    if (uniqueHashes.includes(selectedHash)) {
      const scope = uniqueHashes.length > 1 ? ' It matches one of the APK signer certificates; other signers may also matter.' : ' The selected keystore certificate matches the verified APK signer.';
      const warning = certificateOnly ? ' This certificate does not establish possession of the private signing key.' : '';
      if (keystore?.integrity === 'weak') {
        setComparison('Certificate match, weak integrity', scope.trimStart() + ' This older BKS store has a weak integrity check; its contents may have been altered.' + warning, 'WEAK INTEGRITY');
      } else {
        setComparison('Certificate match', scope.trimStart() + warning, 'MATCH', 'match');
      }
    } else {
      setComparison('Certificates differ', 'The selected keystore certificate does not match the verified APK signer certificate.', 'NO MATCH', 'mismatch');
    }
  }
};

const make = <K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};

const detail = (label: string, value: string | undefined, fingerprint = false): HTMLElement | null => {
  if (!value) return null;
  const row = make('div');
  const heading = make('div', 'detail-label');
  heading.append(make('span', '', label));
  if (fingerprint) {
    const copy = make('button', 'copy-button', 'Copy');
    copy.type = 'button';
    copy.setAttribute('aria-label', `Copy ${label} fingerprint`);
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
        copy.textContent = 'Copied';
      } catch {
        copy.textContent = 'Copy unavailable';
      }
    });
    heading.append(copy);
  }
  row.append(heading, make('div', fingerprint ? 'fingerprint-value' : 'detail-value', value));
  return row;
};

const addDetail = (parent: HTMLElement, label: string, value?: string, fingerprint = false): void => {
  const row = detail(label, value, fingerprint);
  if (row) parent.append(row);
};

const entryLabel = (value?: string): string | undefined => {
  if (value === 'private-key') return 'Private-key entry';
  if (value === 'trusted-certificate') return 'Trusted certificate (no private key)';
  if (value === 'certificate') return 'Public certificate (private key not checked)';
  if (value === 'key-entry') return 'Key entry (private key not unlocked)';
  return value;
};

const renderAlias = (): void => {
  const alias = activeAlias();
  aliasDetails.replaceChildren();
  if (!alias) return;
  const list = make('div', 'detail-list');
  addDetail(list, 'Entry type', entryLabel(alias.entryType));
  addDetail(list, 'Subject', alias.subject);
  addDetail(list, 'Issuer', alias.issuer);
  if (alias.notBefore || alias.notAfter) addDetail(list, 'Certificate validity', [alias.notBefore, alias.notAfter].filter(Boolean).join(' → '));
  addDetail(list, 'SHA-256', alias.sha256, true);
  addDetail(list, 'SHA-1', alias.sha1, true);
  aliasDetails.append(list);
  updateComparison();
};

const showKeystore = (result: KeystoreResult): void => {
  if (!result || !Array.isArray(result.aliases) || !result.aliases.length) throw new Error('This keystore contains no readable certificate entries.');
  if (result.aliases.some((item) => !item || typeof item.alias !== 'string' || !normaliseSha256(item.sha256))) throw new Error('The keystore returned incomplete certificate information.');
  keystore = result;
  byId<HTMLElement>('keystore-format').textContent = `${result.format} inspected`;
  byId<HTMLElement>('keystore-integrity-warning').hidden = result.integrity !== 'weak';
  byId<HTMLElement>('keystore-indicator').classList.toggle('good', result.integrity !== 'weak');
  byId<HTMLElement>('keystore-indicator').classList.toggle('bad', result.integrity === 'weak');
  aliasSelect.replaceChildren();
  for (const alias of result.aliases) {
    const option = document.createElement('option');
    option.value = alias.alias;
    option.textContent = alias.alias;
    aliasSelect.append(option);
  }
  byId<HTMLSpanElement>('alias-count').textContent = `${result.aliases.length} ${result.aliases.length === 1 ? 'alias' : 'aliases'}`;
  ksResultArea.hidden = false;
  renderAlias();
};

const renderSigner = (signer: CertificateInfo, index: number, count: number): HTMLElement => {
  const section = make('div', 'signer-block');
  section.append(make('div', 'signer-title', count > 1 ? `Signer ${index + 1}` : 'Signing certificate'));
  const list = make('div', 'detail-list');
  addDetail(list, 'Subject', signer.subject);
  addDetail(list, 'Issuer', signer.issuer);
  if (signer.scheme) addDetail(list, 'Signing scheme', signer.scheme.toUpperCase());
  if (signer.minSdk !== undefined || signer.maxSdk !== undefined) {
    const lower = signer.minSdk === undefined ? '?' : String(signer.minSdk);
    const upper = signer.maxSdk === undefined ? '?' : String(signer.maxSdk);
    addDetail(list, 'Android API range', `${lower}–${upper}`);
  }
  if (signer.notBefore || signer.notAfter) addDetail(list, 'Certificate validity', [signer.notBefore, signer.notAfter].filter(Boolean).join(' → '));
  addDetail(list, 'SHA-256', signer.sha256, true);
  addDetail(list, 'SHA-1', signer.sha1, true);
  section.append(list);
  return section;
};

const showApk = (result: ApkResult): void => {
  if (!result || typeof result.verified !== 'boolean' || !Array.isArray(result.signers)) throw new Error('The APK verifier returned an incomplete result.');
  apk = result;
  apkResultContent.replaceChildren();
  const heading = make('div', `result-heading${result.verified ? '' : ' bad'}`);
  heading.append(make('span', `status-indicator ${result.verified ? 'good' : 'bad'}`));
  heading.append(make('span', '', result.verified ? 'APK signature verified' : 'APK signature not verified'));
  apkResultContent.append(heading);
  if (result.scope) apkResultContent.append(make('p', 'result-message', result.scope));
  if (result.schemes?.length) apkResultContent.append(make('p', 'result-message', `${result.verified ? 'Verified' : 'Detected'} schemes: ${result.schemes.join(', ')}`));
  if (!result.verified && result.signers.length) apkResultContent.append(make('p', 'result-message warning', 'The following certificates are diagnostic only; the APK did not pass signature verification.'));
  if (result.verified && result.signers.length === 0) apkResultContent.append(make('p', 'result-message warning', 'No signing certificate was returned, so this APK cannot be compared.'));
  for (const message of result.errors ?? []) apkResultContent.append(make('p', 'result-message warning', message));
  for (const message of result.warnings ?? []) apkResultContent.append(make('p', 'result-message warning', message));
  result.signers.forEach((signer, index) => apkResultContent.append(renderSigner(signer, index, result.signers.length)));
  apkResultArea.hidden = false;
  updateComparison();
};

const begin = (kind: Job, request: InspectionRequest): void => {
  terminate(kind);
  if (kind === 'keystore') {
    keystore = null;
    ksResultArea.hidden = true;
    aliasDetails.replaceChildren();
  } else {
    apk = null;
    apkResultArea.hidden = true;
    apkResultContent.replaceChildren();
  }
  updateComparison();
  setStatus(kind, 'Preparing local inspection…');
  setBusy(kind, true);
  let worker: Worker;
  try {
    worker = new Worker(new URL('./inspection.worker.ts', import.meta.url), { type: 'module' });
  } catch {
    setBusy(kind, false);
    setStatus(kind, 'Unable to start the local inspector in this browser.', true);
    return;
  }
  if (kind === 'keystore') ksWorker = worker;
  else apkWorker = worker;
  worker.onmessage = (event: MessageEvent<InspectionResponse>) => {
    if ((kind === 'keystore' ? ksWorker : apkWorker) !== worker) return;
    const message = event.data;
    if (message.type === 'progress') {
      setStatus(kind, message.message);
      return;
    }
    try {
      if (message.type === 'keystore-result' && kind === 'keystore') showKeystore(message.result);
      else if (message.type === 'apk-result' && kind === 'apk') showApk(message.result);
      else if (message.type === 'error') throw new Error(message.message);
      else throw new Error('The inspector returned an unexpected response.');
      setStatus(kind, '');
    } catch (error) {
      setStatus(kind, error instanceof Error ? error.message : 'Unable to inspect this file.', true);
    }
    terminate(kind);
  };
  worker.onerror = (event) => {
    if ((kind === 'keystore' ? ksWorker : apkWorker) !== worker) return;
    event.preventDefault();
    setStatus(kind, 'The local inspector could not complete. Please try again.', true);
    terminate(kind);
  };
  try {
    worker.postMessage(request);
  } catch {
    setStatus(kind, 'Unable to read this file in the browser.', true);
    terminate(kind);
  }
};

const setSelectedFile = (kind: Job, file: File | null): void => {
  if (kind === 'keystore') {
    if (ksWorker) return;
    keystoreFile = file;
    keystore = null;
    ksResultArea.hidden = true;
    aliasDetails.replaceChildren();
    byId<HTMLElement>('keystore-file-title').textContent = file?.name ?? 'Choose a keystore file ↗';
    byId<HTMLElement>('keystore-file-hint').textContent = file ? `${formatSize(file.size)} · choose another file` : 'or drag and drop · keystore or certificate';
  } else {
    if (apkWorker) return;
    apkFile = file;
    apk = null;
    apkResultArea.hidden = true;
    apkResultContent.replaceChildren();
    byId<HTMLElement>('apk-file-title').textContent = file?.name ?? 'Choose an APK file ↗';
    byId<HTMLElement>('apk-file-hint').textContent = file ? `${formatSize(file.size)} · choose another file` : 'or drag and drop · .apk';
  }
  setStatus(kind, '');
  setBusy(kind, false);
  updateComparison();
};

ksFileInput.addEventListener('change', () => setSelectedFile('keystore', ksFileInput.files?.[0] ?? null));
apkFileInput.addEventListener('change', () => setSelectedFile('apk', apkFileInput.files?.[0] ?? null));

const setupDrop = (id: string, kind: Job): void => {
  const zone = byId<HTMLElement>(id);
  for (const name of ['dragenter', 'dragover']) zone.addEventListener(name, (event) => {
    event.preventDefault();
    if (kind === 'keystore' ? !ksWorker : !apkWorker) zone.classList.add('dragging');
  });
  for (const name of ['dragleave', 'drop']) zone.addEventListener(name, (event) => {
    event.preventDefault();
    zone.classList.remove('dragging');
  });
  zone.addEventListener('drop', (event) => {
    const file = (event as DragEvent).dataTransfer?.files[0];
    if (file) setSelectedFile(kind, file);
  });
};
setupDrop('keystore-drop', 'keystore');
setupDrop('apk-drop', 'apk');
// Prevent a file dropped outside a target from navigating away from the app.
for (const name of ['dragover', 'drop']) window.addEventListener(name, (event) => {
  if ((event as DragEvent).dataTransfer?.types.includes('Files')) event.preventDefault();
});

byId<HTMLFormElement>('keystore-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!keystoreFile || ksWorker) return;
  const password = passwordInput.value;
  passwordInput.value = '';
  begin('keystore', { type: 'keystore', file: keystoreFile, password });
});
byId<HTMLFormElement>('apk-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!apkFile || apkWorker) return;
  begin('apk', { type: 'apk', file: apkFile });
});
ksCancel.addEventListener('click', () => { terminate('keystore'); setStatus('keystore', 'Inspection cancelled.'); });
apkCancel.addEventListener('click', () => { terminate('apk'); setStatus('apk', 'Inspection cancelled.'); });
aliasSelect.addEventListener('change', renderAlias);
passwordToggle.addEventListener('click', () => {
  const isVisible = passwordInput.type === 'text';
  passwordInput.type = isVisible ? 'password' : 'text';
  passwordToggle.setAttribute('aria-pressed', String(!isVisible));
  passwordToggle.setAttribute('aria-label', isVisible ? 'Show password' : 'Hide password');
});
byId<HTMLButtonElement>('reset-all').addEventListener('click', () => {
  terminate('keystore');
  terminate('apk');
  ksFileInput.value = '';
  apkFileInput.value = '';
  passwordInput.value = '';
  passwordInput.type = 'password';
  passwordToggle.setAttribute('aria-pressed', 'false');
  passwordToggle.setAttribute('aria-label', 'Show password');
  setSelectedFile('keystore', null);
  setSelectedFile('apk', null);
});
