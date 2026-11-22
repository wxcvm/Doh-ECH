#!/usr/bin/env node
// Real-network probe: DNS timings use the supplied DoH endpoint; TLS and TTFB
// use the machine's normal network stack (NOT resolved through that DoH endpoint).
import { randomInt } from 'node:crypto';
import tls from 'node:tls';
import https from 'node:https';
import { performance } from 'node:perf_hooks';

const args=process.argv.slice(2);
const option=name=>{const i=args.indexOf(name);return i<0?null:args[i+1];};
const resolver=option('--resolver');
const domains=(option('--domains')||'www.taobao.com,www.google.com').split(',').map(s=>s.trim()).filter(Boolean);
const count=Number(option('--samples')||3);
const recordTypes=(option('--types')||'A').split(',').map(x=>x.trim().toUpperCase());
const typeCodes={A:1,AAAA:28,HTTPS:65};
const timeout=Number(option('--timeout-ms')||5000);
if(!resolver || !Number.isInteger(count) || count<1 || count>30 ||
   !Number.isInteger(timeout) || timeout<500 || timeout>30000 ||
   domains.length<1 || domains.length>20 ||
   !recordTypes.length || new Set(recordTypes).size!==recordTypes.length ||
   recordTypes.some(t=>!Object.hasOwn(typeCodes,t)) ||
   domains.some(d=>d.length>253 || !/^[a-z0-9.-]+$/i.test(d) || d.split('.').some(l=>!l || l.length>63))) {
  console.error('Usage: node scripts/benchmark-balanced.mjs --resolver https://YOUR-WORKER/ech?enhance=balanced\\&cnEcs=auto [--domains www.taobao.com,www.google.com] [--types A,AAAA,HTTPS] [--samples 3] [--timeout-ms 5000]');
  process.exit(2);
}
let url;
try {url=new URL(resolver);if(url.protocol!=='https:' || !url.hostname || url.username || url.password)throw Error(); }
catch {console.error('Resolver must be an HTTPS URL without credentials');process.exit(2);}
function wire(name,type=1) {
  const labels=name.split('.').map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s,'ascii')]));
  const packet=Buffer.concat([Buffer.alloc(12),...labels,Buffer.from([0,0,type,0,1])]);
  packet.writeUInt16BE(randomInt(65536),0);packet.writeUInt16BE(0x0100,2);packet.writeUInt16BE(1,4);
  return packet;
}
async function doh(name,type) {
  const query=wire(name,typeCodes[type]),start=performance.now();
  const signal=AbortSignal.timeout(timeout);
  try {
    const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/dns-message','Accept':'application/dns-message'},body:query,signal,cache:'no-store'});
    const bytes=Buffer.from(await response.arrayBuffer());
    if(!response.ok || !response.headers.get('content-type')?.toLowerCase().startsWith('application/dns-message') ||
       bytes.length<query.length || bytes.readUInt16BE(0)!==query.readUInt16BE(0) ||
       !(bytes.readUInt16BE(2)&0x8000) || (bytes.readUInt16BE(2)&0x0200) ||
       bytes.readUInt16BE(4)!==1 || !bytes.subarray(12,query.length).equals(query.subarray(12)))
      throw Error('invalid DoH response: HTTP '+response.status);
    return {ms:Math.round((performance.now()-start)*100)/100,rcode:bytes.readUInt16BE(2)&15,answers:bytes.readUInt16BE(6),
      route:response.headers.get('x-dns-route'),cache:response.headers.get('x-cache')};
  } catch(e) {return {error:String(e.message||e)};}
}
function handshake(name) {
  return new Promise(resolve=>{
    const start=performance.now(),socket=tls.connect({host:name,port:443,servername:name,rejectUnauthorized:true});
    let done=false;
    const finish=value=>{if(done)return;done=true;socket.destroy();resolve(value);};
    socket.setTimeout(timeout,()=>finish({error:'TLS timeout'}));
    socket.once('secureConnect',()=>finish({ms:Math.round((performance.now()-start)*100)/100}));
    socket.once('error',e=>finish({error:e.message}));
  });
}
function ttfb(name) {
  return new Promise(resolve=>{
    const start=performance.now();
    const req=https.get({hostname:name,path:'/',timeout,headers:{'User-Agent':'Doh-ECH-benchmark/1.0'}},res=>{
      const ms=Math.round((performance.now()-start)*100)/100;
      res.destroy();resolve({ms,status:res.statusCode});
    });
    req.on('timeout',()=>req.destroy(Error('HTTP timeout')));
    req.on('error',e=>resolve({error:e.message}));
  });
}
const output={timestamp:new Date().toISOString(),resolver:url.toString(),samples:count,recordTypes,timeoutMs:timeout,
  caveat:'DoH measurements use resolver; TLS and HTTPS TTFB use local system DNS and network. First DoH request is not guaranteed cold (edge cache may already be warm). No China-mainland claim unless run there.',
  results:[]};
for(const name of domains) {
  const dnsByType={};
  for(const type of recordTypes){
    const samples=[];
    for(let i=0;i<count;i++)samples.push(await doh(name,type));
    dnsByType[type]={firstObserved:samples[0],subsequent:samples.slice(1)};
  }
  const dns=dnsByType.A;
  const tlsSamples=[],ttfbSamples=[];
  for(let i=0;i<count;i++){tlsSamples.push(await handshake(name));ttfbSamples.push(await ttfb(name));}
  output.results.push({domain:name,dnsByType,...(dns?{dnsFirstObserved:dns.firstObserved,dnsSubsequent:dns.subsequent}:{}),tls:tlsSamples,ttfb:ttfbSamples});
}
console.log(JSON.stringify(output,null,2));
if(output.results.some(r=>Object.values(r.dnsByType).some(t=>[t.firstObserved,...t.subsequent].some(sample=>sample.error))))process.exitCode=1;
