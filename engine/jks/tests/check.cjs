const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
require(path.join(dir, 'assets', 'wasm_exec.js'));
const go = new Go();
function fp(digest) {
  return digest.toUpperCase().match(/../g).join(':');
}
function read(name) { return new Uint8Array(fs.readFileSync(path.join(dir,name))); }
function digest(name, algorithm) {
  return fp(crypto.createHash(algorithm).update(fs.readFileSync(path.join(dir,name))).digest('hex'));
}
WebAssembly.instantiate(fs.readFileSync(path.join(dir,'assets','jks.wasm')),go.importObject).then(({instance})=>{
  go.run(instance);
  const bytes=read('multiple.jks');
  const result=inspectJks(bytes,'café🔑pass');
  assert.equal(result.ok,true,JSON.stringify(result));
  assert.equal(result.format,'JKS');
  assert.equal(result.aliases.length,3);
  const unicode=result.aliases.find(e=>e.alias==='café-😀');
  const alpha=result.aliases.find(e=>e.alias==='alpha');
  const trust=result.aliases.find(e=>e.alias==='trusted');
  assert.ok(unicode && alpha && trust);
  assert.equal(unicode.entryType,'private-key');
  assert.equal(alpha.entryType,'private-key');
  assert.equal(trust.entryType,'trusted-certificate');
  assert.equal(alpha.sha256,digest('alpha.der','sha256'));
  assert.equal(alpha.sha1,digest('alpha.der','sha1'));
  assert.equal(unicode.sha256,digest('unicode.der','sha256'));
  assert.equal(trust.sha256,digest('alpha.der','sha256'));
  assert.ok(alpha.subject.includes('CN=Alpha'));
  assert.ok(alpha.issuer.includes('CN=Alpha'));
  assert.ok(Date.parse(alpha.notBefore));
  assert.ok(Date.parse(alpha.notAfter));
  const badPassword=inspectJks(bytes,'wrong');
  assert.equal(badPassword.error.code,'INTEGRITY_ERROR');
  const damaged=bytes.slice(); damaged[damaged.length-1]^=1;
  assert.equal(inspectJks(damaged,'café🔑pass').error.code,'INTEGRITY_ERROR');
  const malformed=bytes.slice(); malformed.fill(255,8,12);
  assert.equal(inspectJks(malformed,'café🔑pass').error.code,'INVALID_JKS');
  for (const file of ['modern.p12', 'legacy.p12']) {
    const p12=read(file);
    const result=inspectJks(p12,'café🔑pass');
    assert.equal(result.ok,true,`${file}: ${JSON.stringify(result)}`);
    assert.equal(result.format,'PKCS#12');
    assert.equal(result.aliases.length,3);
    const byAlias=Object.fromEntries(result.aliases.map(e=>[e.alias,e]));
    assert.equal(byAlias.alpha.entryType,'private-key');
    assert.equal(byAlias.alpha.sha256,digest('alpha.der','sha256'));
    assert.equal(byAlias['café-😀'].sha256,digest('unicode.der','sha256'));
    assert.equal(byAlias.trusted.entryType,'trusted-certificate');
    assert.equal(byAlias.trusted.sha256,digest('alpha.der','sha256'));
    assert.equal(inspectJks(p12,'wrong').error.code,'INTEGRITY_ERROR');
    const corrupt=p12.slice(); corrupt[corrupt.length-1]^=1;
    assert.notEqual(inspectJks(corrupt,'café🔑pass').ok,true);
  }
  const emptyP12=inspectJks(read('empty.p12'),'');
  assert.equal(emptyP12.ok,true,JSON.stringify(emptyP12));
  assert.equal(emptyP12.aliases[0].sha256,digest('alpha.der','sha256'));
  assert.equal(inspectJks(read('empty.p12'),'wrong').error.code,'INTEGRITY_ERROR');
  if (fs.existsSync(path.join(dir,'openssl.p12'))) {
    const openssl=inspectJks(read('openssl.p12'),'testing123');
    assert.equal(openssl.ok,true,JSON.stringify(openssl));
    assert.equal(openssl.aliases[0].sha256,digest('alpha.der','sha256'));
  }
  const jce=inspectJks(read('store.jceks'),'café🔑pass');
  assert.equal(jce.ok,true,JSON.stringify(jce));
  assert.equal(jce.format,'JCEKS');
  assert.equal(jce.aliases.find(e=>e.alias==='jce').sha256,digest('jce.der','sha256'));
  assert.equal(jce.aliases.find(e=>e.alias==='trusted').entryType,'trusted-certificate');
  assert.equal(inspectJks(read('store.jceks'),'wrong').error.code,'INTEGRITY_ERROR');
  assert.equal(inspectJks(read('secret.jceks'),'café🔑pass').error.code,'INVALID_JCEKS');
  for (const file of ['alpha.der','alpha.pem']) {
    const cert=inspectJks(read(file),'');
    assert.equal(cert.ok,true,`${file}: ${JSON.stringify(cert)}`);
    assert.equal(cert.format,'X.509');
    assert.equal(cert.aliases[0].entryType,'certificate');
    assert.equal(cert.aliases[0].sha256,digest('alpha.der','sha256'));
  }
  const privateOnly=inspectJks(read('private.pk8'),'');
  assert.equal(privateOnly.ok,false);
  assert.match(privateOnly.error.message,/certificate.*private key/i);
  const mixed=Buffer.concat([Buffer.from('-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n'),fs.readFileSync(path.join(dir,'alpha.pem'))]);
  assert.equal(inspectJks(new Uint8Array(mixed),'').aliases[0].sha256,digest('alpha.der','sha256'));
  const empty=inspectJks(read('empty.jks'),'');
  assert.equal(empty.ok,true,JSON.stringify(empty));
  assert.equal(empty.aliases[0].alias,'empty-pass');
  assert.equal(empty.aliases[0].sha256,digest('alpha.der','sha256'));
  assert.equal(inspectJks(read('empty.jks'),'wrong').error.code,'INTEGRITY_ERROR');
  console.log('WASM integration passed: JKS, modern/legacy PKCS#12, JCEKS, DER/PEM certificates, multiple aliases, Unicode, empty JKS password, integrity failures, and private-key-only guidance.');
  process.exit(0);
}).catch(error=>{ console.error(error); process.exit(1); });
