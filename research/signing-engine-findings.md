# Signing engine research

These are feasibility experiments from 20 November 2026, not a completed browser security review or application test. The [ProjectForge manifest](../projectforge.json) remains the canonical plan.

## JKS through Go/WASM

`keystore-go/v4` v4.5.0 was compiled to WebAssembly with Go 1.27.4 and executed through Node 26.13.1. A disposable `keytool`-generated JKS contained one private-key entry with a separate key password. Calling `Load`, `Aliases`, and `GetPrivateKeyEntryCertificateChain` returned its certificate without supplying the key password. Its SHA-256 matched `keytool -list -v`; a wrong store password returned an integrity error.

This establishes a narrow Node/WASM path only. Real-browser execution, multiple and non-ASCII aliases, malformed files, empty passwords, trusted certificate entries, resource limits and PKCS#12 require independent tests. Wrong password and damaged integrity should be reported as possible causes of the same failure unless they can actually be distinguished.

Source: [keystore-go](https://github.com/pavlo-v-chernykh/keystore-go).

## APK verification

`apksig-go` v1.1.0 at commit `a0389a9d7f83032504713ac6052f85edfb52f64b` was compiled to WebAssembly and run under Node against public [AOSP apksig golden fixtures](https://android.googlesource.com/platform/tools/apksig/+/refs/heads/main/src/test/resources/com/android/apksig/). Results were compared with Android SDK Build Tools 37.0.0 `apksigner` for API 24 through 35.

For `golden-aligned-v2-out.apk`, official `apksigner` returned `Verifies` and v2 `true`. The candidate returned overall `verified: false`, citing the APK's manifest minimum SDK of 23, even though both tools were explicitly given the 24–35 range. This disagreement must be explained and resolved before accepting the candidate. The reference command was:

```sh
apksigner verify --verbose --print-certs --min-sdk-version 24 --max-sdk-version 35 golden-aligned-v2-out.apk
```

For one v1/v2/v3 fixture modified in `classes.dex`, both tools rejected overall verification. The candidate nevertheless exposed individual signer objects marked verified, so the UI must check the overall verification and content-integrity outcome before displaying a verified match. One tampering test cannot establish complete correctness.

The candidate's browser interface currently accepts an entire `Uint8Array` and copies it into Go memory. It has not been benchmarked with 100 MB APKs. Its signing-scheme coverage, signer selection, key rotation, v3.1 output, licenses, and behavior in actual browsers remain release gates.

Source: [apksig-go](https://github.com/agusibrahim/apksig-go); [Android apksigner](https://developer.android.com/tools/apksigner).
