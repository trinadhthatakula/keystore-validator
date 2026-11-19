const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
require(path.join(dir,'assets','wasm_exec.js'));
const go = new Go();
const read = name => new Uint8Array(fs.readFileSync(path.join(dir,name)));
const hash = name => crypto.createHash('sha256').update(fs.readFileSync(path.join(dir,name))).digest('hex').toUpperCase().match(/../g).join(':');
WebAssembly.instantiate(fs.readFileSync(path.join(dir,'assets','jks.wasm')),go.importObject).then(({instance})=>{
  void go.run(instance);
  for (const item of [
    {file:'store.bks',pass:'testpass123',format:'BKS',alias:'alpha',cert:'alpha.der'},
    {file:'old.bks',pass:'testpass123',format:'BKS',alias:'old',cert:'old.der',weak:true},
    {file:'store.uber',pass:'testpass123',format:'UBER',alias:'uber',cert:'uber.der'},
    {file:'unicode.uber',pass:'café🔑pass',format:'UBER',alias:'unicode',cert:'uber-unicode.der'},
    {file:'empty.uber',pass:'',format:'UBER',alias:'empty-pass',cert:'alpha.der'},
    {file:'store.bcfks',pass:'café🔑pass',format:'BCFKS',alias:'fips',cert:'fips.der'},
    {file:'scrypt.bcfks',pass:'café🔑pass',format:'BCFKS',alias:'fips',cert:'fips.der'},
    {file:'sha3.bcfks',pass:'café🔑pass',format:'BCFKS',alias:'fips',cert:'fips.der'},
    {file:'empty.bcfks',pass:'',format:'BCFKS',alias:'empty',cert:'fips.der'},
  ]) {
    const result=inspectJks(read(item.file),item.pass);
    assert.equal(result.ok,true,JSON.stringify(result));
    assert.equal(result.format,item.format);
    assert.equal(result.integrity==='weak',!!item.weak);
    assert.equal(result.aliases.find(x=>x.alias===item.alias).sha256,hash(item.cert));
    assert.notEqual(inspectJks(read(item.file),'wrong').ok,true);
  }
  console.log('WASM integration passed: BKS v1/v2, UBER and BCFKS certificates, integrity and wrong passwords.');
  process.exit(0);
}).catch(e=>{console.error(e);process.exit(1)});
