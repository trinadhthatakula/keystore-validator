/** Certificate information is public; private key material is never returned. */
export interface CertificateInfo {
  sha256: string;
  sha1?: string;
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  scheme?: string;
  minSdk?: number;
  maxSdk?: number;
}

export interface KeystoreAlias extends CertificateInfo {
  alias: string;
  entryType?: string;
}

export interface KeystoreResult {
  format: string;
  aliases: KeystoreAlias[];
  integrity?: 'weak';
}

export interface ApkResult {
  verified: boolean;
  signers: CertificateInfo[];
  schemes?: string[];
  warnings?: string[];
  errors?: string[];
  scope?: string;
}

export type InspectionRequest =
  | { type: 'keystore'; file: File; password: string }
  | { type: 'apk'; file: File };

export type InspectionResponse =
  | { type: 'progress'; message: string; progress?: number }
  | { type: 'keystore-result'; result: KeystoreResult }
  | { type: 'apk-result'; result: ApkResult }
  | { type: 'error'; message: string };
