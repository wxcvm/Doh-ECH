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

// A resolver can succeed once and then fail. Later samples must affect the
// command exit status rather than being silently reported as a successful run.
// Stub only fetch: TLS/TTFB probes to localhost remain independent.
const preload=`let calls=0;
globalThis.fetch=async (_url,init)=>{
  if(calls++>0)throw Error('simulated subsequent DNS outage');
  const q=Buffer.from(init.body),p=Buffer.from(q);
  p.writeUInt16BE(0x8180,2);
  return new Response(p,{headers:{'Content-Type':'application/dns-message'}});
};`;
const laterFailure=spawnSync(process.execPath,[
  '--import','data:text/javascript,'+encodeURIComponent(preload),
  'scripts/benchmark-balanced.mjs','--resolver','https://example.com/ech?enhance=balanced&cnEcs=auto',
  '--domains','localhost','--types','A','--samples','2','--timeout-ms','500'
],{encoding:'utf8',timeout:8000});
assert.equal(laterFailure.status,1,laterFailure.stderr||laterFailure.stdout);
const report=JSON.parse(laterFailure.stdout);
assert.equal(report.results[0].dnsByType.A.firstObserved.rcode,0);
assert.match(report.results[0].dnsByType.A.subsequent[0].error,/simulated subsequent DNS outage/);

// DNS can succeed while the independent TLS/TTFB probes fail. Report that
// failure to automation callers rather than returning a misleading success.
const dnsSuccessPreload=`globalThis.fetch=async (_url,init)=>{
  const p=Buffer.from(init.body);
  p.writeUInt16BE(0x8180,2);
  return new Response(p,{headers:{'Content-Type':'application/dns-message'}});
};`;
const networkFailure=spawnSync(process.execPath,[
  '--import','data:text/javascript,'+encodeURIComponent(dnsSuccessPreload),
  'scripts/benchmark-balanced.mjs','--resolver','https://example.com/ech?enhance=balanced&cnEcs=auto',
  '--domains','localhost','--types','A','--samples','1','--timeout-ms','500'
],{encoding:'utf8',timeout:8000});
assert.equal(networkFailure.status,1,networkFailure.stderr||networkFailure.stdout);
const networkReport=JSON.parse(networkFailure.stdout);
assert.equal(networkReport.results[0].dnsByType.A.firstObserved.rcode,0);
assert.ok([...networkReport.results[0].tls,...networkReport.results[0].ttfb].some(s=>s.error));
