import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const run=(...args)=>spawnSync(process.execPath,['scripts/benchmark-balanced.mjs','--resolver','https://example.com/ech?enhance=balanced&cnEcs=auto',...args],{encoding:'utf8',timeout:3000});
for(const types of ['TXT','A,A','A,BOGUS','HTTPS,HTTPS']){
  const result=run('--types',types);
  assert.equal(result.status,2,types+' must fail validation without network');
}
for(const types of ['AAAA,HTTPS','A,AAAA,HTTPS']){
  const result=run('--types',types,'--domains','bad..name');
  assert.equal(result.status,2,'invalid domain must fail without network for '+types);
}
console.log('benchmark CLI argument validation passed');
