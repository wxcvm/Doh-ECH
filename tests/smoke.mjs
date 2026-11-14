import assert from 'node:assert/strict';
import worker from '../_worker.js';

// Lightweight Cloudflare runtime mocks. Tests must not perform network requests.
const calls = [];
const cache = new Map();
let simulateBinaryOutage = false;
let binaryReplyOverride = null;
let domesticWireOutage = false;
const wireBodies = [];
let ecsReject = false;
let ecsMismatch = false;
globalThis.caches = {
  default: {
    async match(key) { return cache.get(key instanceof Request ? key.url : String(key))?.clone() || undefined; },
    async put(key, response) { cache.set(key instanceof Request ? key.url : String(key), response.clone()); }
  }
};
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input));
  calls.push(url.href);
  if (url.hostname === 'untrusted.invalid' || url.hostname === '127.0.0.1') {
    throw new Error('An untrusted subscription URL was fetched');
  }
  if (url.hostname === 'feeds.example') {
    return new Response('203.0.113.55\n', { headers: { 'Content-Type': 'text/plain' } });
  }
  if ((init.method || 'GET') === 'POST' && init.body) {
    const incoming=Buffer.from(Buffer.from(init.body));
    wireBodies.push({host:url.hostname,body:incoming});
    const hasInjected=incoming.subarray(-11).toString('hex').startsWith('00080007000118') || incoming.subarray(-15).toString('hex').startsWith('0008000b000238');
    if(ecsReject && hasInjected) return new Response('no ECS',{status:503});
    if(ecsMismatch && hasInjected) {const reply=Buffer.from(incoming);reply.writeUInt16BE(0x8180,2);reply[reply.length-1]^=1;return new Response(reply,{headers:{'Content-Type':'application/dns-message'}});}
    if (simulateBinaryOutage || (domesticWireOutage && ['dns.alidns.com','doh.pub'].includes(url.hostname))) return new Response('temporarily unavailable', { status: 503 });
    if (binaryReplyOverride) {
      return new Response(binaryReplyOverride(Buffer.from(incoming)), {
        headers: { 'Content-Type': 'application/dns-message' }
      });
    }
    if (url.hostname === 'dns.alidns.com') {
      return new Response('not a DNS response', { headers: { 'Content-Type': 'text/html' } });
    }
    const reply = Buffer.from(incoming);
    if (reply.length < 12) throw new Error('Invalid test query');
    reply.writeUInt16BE(0x8180, 2);
    reply.writeUInt16BE(0, 6);
    reply.writeUInt16BE(0, 8);
    return new Response(reply, { headers: { 'Content-Type': 'application/dns-message' } });
  }
  if (url.searchParams.has('name') && url.searchParams.has('type')) {
    const name = url.searchParams.get('name');
    const type = Number(url.searchParams.get('type'));
    const error = url.hostname === 'dns.alidns.com' && name === 'github.com';
    if (name === 'alidns-object.example.cn' || name === 'ecs-rejected.example.cn' || name === 'wrong-question.example.cn') {
      const question = {name: name === 'wrong-question.example.cn' ? 'different.example.cn.' : name + '.', type};
      if (url.hostname === 'cloudflare-dns.com') throw new Error('Domestic DNS must not use foreign upstream');
      if (name === 'ecs-rejected.example.cn' && url.searchParams.has('edns_client_subnet')) {
        return Response.json({Status:2,Question:question});
      }
      // Only AliDNS succeeds, with its real single-object Question shape.
      if (url.hostname !== 'dns.alidns.com') return new Response('upstream failure',{status:503});
      return Response.json({Status:0,Question:question,Answer:[{name,type,TTL:50,data:'203.0.113.52'}]});
    }
    if (name === 'https-panel.example' && type === 65) {
      return Response.json({Status:0,Question:[{name:name+'.',type}],Answer:[
        {name,type,TTL:60,data:'0 svc.example.'},{name,type,TTL:40,data:'1 . alpn=h2,h3'}
      ]});
    }
    if (name === 'https-failure.example' && type === 65) return Response.json({Status:2,Question:[{name:name+'.',type}]});
    if (name === 'www.facebook.com' && type === 65) {
      return Response.json({ Status: 0, Question: [{ name: name + '.', type }],
        Answer: [{ name, type, TTL: 42, data: '1 . alpn=h2 ech=AAECAw==' }] });
    }
    if (name === 'owner.example' && type === 1) {
      const ecs = url.searchParams.get('edns_client_subnet');
      const ips = ecs === '192.0.2.0/24' ? ['104.16.1.1'] :
        ecs === '192.0.3.0/24' ? ['104.16.1.1','203.0.113.17'] : ['203.0.113.17'];
      return Response.json({ Status: 0, Question: [{ name: name + '.', type }],
        Answer: ips.map(data => ({ name, type, TTL: 20, data })) });
    }
    if (name === 'hedge-failure.example' && url.hostname !== 'cloudflare-dns.com') {
      return Response.json({ Status: 2, Question: [{ name: name + '.', type }] });
    }
    if (name === 'ttl.example' || name === 'zero.example' || name === 'missing.example.cn' || name === 'failure.example.cn') {
      const status = name === 'missing.example.cn' ? 3 : name === 'failure.example.cn' ? 2 : 0;
      return Response.json({ Status: status, Question: [{ name: name + '.', type }],
        Answer: status === 0 ? [{ name, type, TTL: name === 'zero.example' ? 0 : 12, data: '203.0.113.42' }] : [] });
    }
    if (name === 'ech-race.example' && type === 65) {
      return Response.json({ Status: 0, Question: [{ name: name + '.', type }],
        Answer: [{ name, type, TTL: 60, data: url.hostname === 'cloudflare-dns.com' ? '1 . alpn=h2 ech=AAECAw==' : '1 . alpn=h2' }] });
    }
    return Response.json({
      Status: error ? 2 : 0,
      Question: [{ name: name + '.', type }],
      Answer: error ? [] : (type === 1 || type === 28 ? [{ name, type, TTL: 300, data: type === 1 ? '203.0.113.17' : '2001:db8::17' }] : [])
    });
  }
  if (url.pathname.endsWith('.json')) return Response.json([]);
  return new Response('', { status: 200 });
};

const ctx = { waitUntil(promise) { Promise.resolve(promise).catch(() => {}); } };
const env = {};
function question(name = 'github.com', type = 1, { qclass = 1, ednsDo = false } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  if (ednsDo) header.writeUInt16BE(1, 10);
  const labelBytes = [];
  for (const label of name.split('.')) labelBytes.push(Buffer.from([label.length]), Buffer.from(label));
  labelBytes.push(Buffer.from([0]));
  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(type, 0);
  qtail.writeUInt16BE(qclass, 2);
  const opt = ednsDo
    ? Buffer.from([0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0])
    : Buffer.alloc(0);
  return Buffer.concat([header, ...labelBytes, qtail, opt]);
}
async function request(path, opts = {}, environment = env) {
  return worker.fetch(new Request('https://resolver.example' + path, opts), environment, ctx);
}

const noAuth = await request('/log');
assert.equal(noAuth.status, 404, 'log must be private by default');
const authenticated = await request('/log', { headers: { Authorization: 'Bearer testsecret' } }, { DOH_ADMIN_TOKEN: 'testsecret' });
assert.equal(authenticated.status, 200);

const wrongType = await request('/doh', {
  method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: question()
});
assert.equal(wrongType.status, 415);
const tooLarge = await request('/ech', {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: Buffer.alloc(65536)
});
assert.equal(tooLarge.status, 413);
assert.equal((await request('/doh?dns=not%2Fbase64')).status, 400);
assert.equal((await request('/doh?dns=AA')).status, 400);

const upstream = await request('/doh', {
  method: 'POST',
  headers: { 'Content-Type': 'application/dns-message' },
  body: question()
});
assert.equal(upstream.status, 200);
assert.equal(upstream.headers.get('Cache-Control'), 'no-store');
const wire = Buffer.from(await upstream.arrayBuffer());
assert.equal(wire.readUInt16BE(0), 0x1234, 'forwarded DNS transaction ID must match');

const resolved = await request('/api/query?domain=github.com&type=A');
assert.equal(resolved.status, 200);
const record = await resolved.json();
assert.ok(record.answers?.includes('203.0.113.17'), 'non-Cloudflare domain must retain upstream A answers: '+JSON.stringify({record,calls:calls.slice(-25),cacheKeys:Array.from(cache.keys()).slice(-20)}));

await request('/api/query?domain=example.net&type=A&sub=ip-https%3A%2F%2Funtrusted.invalid%2Flist');
assert.equal(calls.some(s => s.includes('untrusted.invalid')), false, 'SSRF URL must not be fetched');

const allowed = await request(
  '/api/query?domain=cloudflare.com&type=A&sub=ip-https%3A%2F%2Ffeeds.example%2Flist',
  {}, { DOH_ALLOWED_SUB_HOSTS: 'feeds.example' }
);
assert.equal(allowed.status, 200);
const preferred = await allowed.json();
assert.ok(preferred.answers.includes('203.0.113.55'), 'operator-allowlisted subscription should work');

const unsupported = await request('/ech', {
  method: 'POST',
  headers: { 'Content-Type': 'application/dns-message' },
  body: question('github.com', 1, { qclass: 3 })
});
assert.equal(unsupported.status, 200, 'non-IN DNS query should be forwarded');
assert.equal(Buffer.from(await unsupported.arrayBuffer()).readUInt16BE(0), 0x1234);

simulateBinaryOutage = true;
const failed = await request('/doh', {
  method: 'POST',
  headers: { 'Content-Type': 'application/dns-message' },
  body: question('example.net')
});
simulateBinaryOutage = false;
assert.equal(failed.status, 200);
const servfail = Buffer.from(await failed.arrayBuffer());
assert.equal(servfail.readUInt16BE(0), 0x1234, 'SERVFAIL must preserve transaction ID');
assert.equal(servfail.readUInt16BE(2) & 0x000f, 2, 'outage must return DNS SERVFAIL, not HTTP error bytes');
assert.equal(servfail.readUInt16BE(4), 1, 'SERVFAIL must preserve question count');

// EDNS/DNSSEC forwarding must retain valid section counts, including during outages.
const ednsQuery = question('example.net', 1, { ednsDo: true });
const ednsResponse = await request('/ech', {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: ednsQuery
});
const ednsWire = Buffer.from(await ednsResponse.arrayBuffer());
assert.equal(ednsWire.readUInt16BE(10), 1, 'valid upstream OPT must be preserved');
assert.deepEqual(ednsWire.subarray(12), ednsQuery.subarray(12));
simulateBinaryOutage = true;
for (const endpoint of ['/doh', '/ech']) {
  const response = await request(endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: ednsQuery
  });
  const packet = Buffer.from(await response.arrayBuffer());
  assert.equal(packet.readUInt16BE(2) & 15, 2, 'EDNS outage must return SERVFAIL');
  assert.equal(packet.readUInt16BE(0), 0x1234);
  assert.equal(packet.readUInt16BE(4), 1);
  assert.equal(packet.readUInt16BE(10), 0);
  assert.equal(packet.length, question('example.net').length, 'no uncounted OPT bytes may follow question');
  assert.deepEqual(packet.subarray(12), question('example.net').subarray(12));
}
simulateBinaryOutage = false;

function answerPacket(query) {
  const headerAndQuestion = Buffer.from(query);
  headerAndQuestion.writeUInt16BE(0x8180, 2);
  headerAndQuestion.writeUInt16BE(1, 6);
  // Compressed owner name, A/IN, TTL 60, four-byte address.
  return Buffer.concat([headerAndQuestion, Buffer.from([
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 17
  ])]);
}
const forwardingOptions = {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: question('example.net')
};
binaryReplyOverride = answerPacket;
const validAnswer = Buffer.from(await (await request('/doh', forwardingOptions)).arrayBuffer());
assert.equal(validAnswer.readUInt16BE(6), 1, 'valid compressed answer must not be rejected');
assert.deepEqual(validAnswer.subarray(-4), Buffer.from([203, 0, 113, 17]));

const malformedReplies = [
  ['missing question', query => answerPacket(query).subarray(0, 12)],
  ['truncated RR', query => answerPacket(query).subarray(0, -1)],
  ['incorrect question count', query => {
    const packet = answerPacket(query); packet.writeUInt16BE(2, 4); return packet;
  }],
  ['mismatched name', query => {
    const packet = answerPacket(query); packet[13] = 120; return packet;
  }],
  ['mismatched type', query => {
    const packet = answerPacket(query); packet.writeUInt16BE(28, query.length - 4); return packet;
  }],
  ['mismatched class', query => {
    const packet = answerPacket(query); packet.writeUInt16BE(3, query.length - 2); return packet;
  }],
  ['mismatched transaction ID', query => {
    const packet = answerPacket(query); packet.writeUInt16BE(0x4321, 0); return packet;
  }],
  ['mismatched opcode', query => {
    const packet = answerPacket(query); packet.writeUInt16BE(0x8980, 2); return packet;
  }],
  ['compression loop', query => {
    const packet = answerPacket(query); packet[query.length + 1] = query.length; return packet;
  }],
  ['out-of-bounds pointer', query => {
    const packet = answerPacket(query); packet[query.length] = 255; packet[query.length + 1] = 255; return packet;
  }],
  ['unaccounted trailing bytes', query => Buffer.concat([answerPacket(query), Buffer.from([0])])]
];
for (const [description, makeReply] of malformedReplies) {
  binaryReplyOverride = makeReply;
  const response = await request('/doh', forwardingOptions);
  const packet = Buffer.from(await response.arrayBuffer());
  assert.equal(packet.readUInt16BE(2) & 15, 2, `${description} must be rejected with SERVFAIL`);
  assert.equal(packet.length, question('example.net').length, `${description}: fallback must have complete question`);
}
binaryReplyOverride = null;

// Upstream policy sync: test both JSON and binary DNS paths with no live network.
async function apiAnswer(domain, type, params = 'enhance=rule') {
  const response = await request('/api/query?domain=' + encodeURIComponent(domain) + '&type=' + type + '&' + params);
  assert.equal(response.status, 200, domain + ' ' + type);
  return response.json();
}
async function wireAnswer(domain, type, params = 'enhance=rule') {
  const response = await request('/ech?' + params, {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: question(domain, type)
  });
  assert.equal(response.status, 200);
  const packet = Buffer.from(await response.arrayBuffer());
  assert.equal(packet.readUInt16BE(2) & 15, 0, domain + ' DNS RCODE');
  return packet;
}
for (const name of ['mtalk.google.com', 'mobile-gtalk.l.google.com', 'alt7-mtalk.google.com']) {
  assert.deepEqual((await apiAnswer(name, 'A')).answers, ['203.0.113.17']);
  assert.deepEqual((await apiAnswer(name, 'AAAA')).answers, ['2001:db8::17']);
  assert.equal((await wireAnswer(name, 1)).readUInt16BE(6), 1);
  assert.equal((await wireAnswer(name, 28)).readUInt16BE(6), 1);
  const https = await apiAnswer(name, 'HTTPS');
  assert.deepEqual(https.ipv4hints, ['203.0.113.17']);
  assert.deepEqual(https.ipv6hints, ['2001:db8::17']);
}
for (const name of ['dl.google.com', 'music.youtube.com', 'robinfrontend-pa.googleapis.com', 'signaler-pa.googleapis.com']) {
  for (const mode of ['rule', 'full']) {
    assert.deepEqual((await apiAnswer(name, 'A', 'enhance=' + mode)).answers, ['203.0.113.17']);
    assert.deepEqual((await apiAnswer(name, 'AAAA', 'enhance=' + mode)).answers, []);
    assert.equal((await wireAnswer(name, 28, 'enhance=' + mode)).readUInt16BE(6), 0);
    const https = await apiAnswer(name, 'HTTPS', 'enhance=' + mode);
    assert.deepEqual(https.ipv4hints, ['203.0.113.17']);
    assert.equal(https.ipv6hints, undefined);
    assert.equal((await wireAnswer(name, 65, 'enhance=' + mode)).readUInt16BE(6), 1);
  }
  assert.deepEqual((await apiAnswer(name, 'AAAA', 'enhance=off')).answers, ['2001:db8::17']);
}
for (const name of ['google.co.jp', 'www.google.de', 'google.com.au']) {
  assert.deepEqual((await apiAnswer(name, 'A')).answers, []);
  assert.ok((await apiAnswer(name, 'AAAA')).answers.every(ip => ip.startsWith('2001:4860:')));
  assert.ok((await apiAnswer(name, 'AAAA')).answers.length > 0);
  assert.equal((await wireAnswer(name, 1)).readUInt16BE(6), 0);
}
const exact = await apiAnswer('dl.google.com', 'AAAA', 'enhance=rule&rules=' + encodeURIComponent('dl.google.com:2001:db8::99'));
assert.deepEqual(exact.answers, ['2001:db8::99'], 'exact user rule overrides equivalent wildcard');
const unmatched = await wireAnswer('unmatched.example', 65);
assert.equal(unmatched.readUInt16BE(6), 0, 'rule mode must not fabricate HTTPS for an unmatched name');
assert.deepEqual((await apiAnswer('cloudflare.com', 'AAAA', 'enhance=off&nocf6=false')).answers, ['2001:db8::17']);
assert.deepEqual((await apiAnswer('cloudflare.com', 'AAAA', 'enhance=off&nocf6=true')).answers, []);
assert.deepEqual((await apiAnswer('cloudflare.com', 'AAAA', 'enhance=off')).answers, []);
assert.deepEqual((await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&nocf6=false')).ipv6hints, ['2001:db8::17']);
assert.equal((await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&nocf6=true')).ipv6hints, undefined);
// Cache keys use canonical client subnet, resolver policy and selection mode.
const ecsCalls = name => calls.filter(c => new URL(c).searchParams.get('name') === name);
await apiAnswer('ecs.example', 'A', 'enhance=off&clientIp=192.0.2.123');
assert.equal(new URL(ecsCalls('ecs.example')[0]).searchParams.get('edns_client_subnet'), '192.0.2.0/24');
let count = ecsCalls('ecs.example').length;
await apiAnswer('ECS.EXAMPLE.', 'A', 'enhance=off&clientIp=192.0.2.222');
assert.equal(ecsCalls('ecs.example').length, count, 'same IPv4 prefix should hit cache');
await apiAnswer('ecs.example', 'A', 'enhance=off&clientIp=192.0.3.1');
assert.ok(ecsCalls('ecs.example').length > count, 'different subnet must not reuse result');
await apiAnswer('ecs6.example', 'A', 'enhance=off&clientIp=2001:db8:abcd:12ff::42');
assert.equal(new URL(ecsCalls('ecs6.example')[0]).searchParams.get('edns_client_subnet'), '2001:db8:abcd:1200::/56');
count = ecsCalls('ecs6.example').length;
await apiAnswer('ecs6.example', 'A', 'enhance=off&clientIp=2001:0db8:abcd:12aa:0:0:0:1');
assert.equal(ecsCalls('ecs6.example').length, count, 'equivalent IPv6 /56 must share cache');
await apiAnswer('bad-ecs.example', 'A', 'enhance=off&clientIp=2001::db8::1');
assert.equal(new URL(ecsCalls('bad-ecs.example')[0]).searchParams.has('edns_client_subnet'), false);
const ttl = await apiAnswer('ttl.example', 'A', 'enhance=off');
assert.equal(ttl.ttl, 12);
const ttlKey = [...cache.keys()].find(k => k.includes('/upstream-v2/') && k.includes('/ttl.example/'));
assert.ok(ttlKey);
const old = cache.get(ttlKey);
const headers = new Headers(old.headers);
headers.set('X-DNS-Stored-At', String(Date.now() - 5000));
cache.set(ttlKey, new Response(await old.clone().text(), { headers }));
const cached = await apiAnswer('ttl.example', 'A', 'enhance=off');
assert.ok(cached.ttl <= 7 && cached.ttl > 0, 'cache hit must age TTL');
const wireTtl = await wireAnswer('ttl.example', 1, 'enhance=off');
assert.ok(wireTtl.readUInt32BE(question('ttl.example').length + 6) <= 7, 'wire TTL must age too');
headers.set('X-DNS-Stored-At', String(Date.now() - 20000));
cache.set(ttlKey, new Response(await old.clone().text(), { headers }));
count = ecsCalls('ttl.example').length;
await apiAnswer('ttl.example', 'A', 'enhance=off');
assert.ok(ecsCalls('ttl.example').length > count, 'expired cache must refetch');
await apiAnswer('zero.example', 'A', 'enhance=off');
count = ecsCalls('zero.example').length;
await apiAnswer('zero.example', 'A', 'enhance=off');
assert.ok(ecsCalls('zero.example').length > count, 'TTL zero must not cache');
for (const [name, rcode] of [['missing.example.cn',3], ['failure.example.cn',2]]) {
  assert.equal((await apiAnswer(name, 'A', 'enhance=off')).rcode, rcode);
  const result = await request('/ech', { method:'POST', headers:{'Content-Type':'application/dns-message'}, body:question(name) });
  assert.equal(Buffer.from(await result.arrayBuffer()).readUInt16BE(2) & 15, rcode);
}
const ech = await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&ech=ech-race.example');
assert.equal(ech.ech, 'AAECAw==', 'ECH lookup must prefer a record that actually contains ECH');
const json = await request('/api/query?domain=ecs.example&type=A&clientIp=192.0.2.1');
assert.equal(json.headers.get('Cache-Control'), 'no-store');
// ECH RR lifetime must not outlive its actual configuration; fake aliases follow it too.
assert.ok(ech.ttl >= 0 && ech.ttl <= 60);
for (const name of ['cloudflare.com', 'cf.ech']) {
  const body = question(name, 65);
  const path = '/ech?enhance=off&ech=ech-race.example';
  const post = await request(path, { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body });
  const get = await request(path + '&dns=' + body.toString('base64url'));
  for (const response of [post, get]) {
    const packet = Buffer.from(await response.arrayBuffer());
    assert.equal(packet.readUInt16BE(2) & 15, 0);
    assert.equal(packet.readUInt16BE(6), 1);
    assert.ok(packet.readUInt32BE(body.length + 6) <= 60, name + ' ECH TTL');
    assert.equal(response.headers.get('X-Cache'), null, 'HTTPS RR must not use static address cache');
  }
}
const unavailable = await request('/ech?ech=no-ech.example', { method: 'POST', headers: {'Content-Type':'application/dns-message'}, body: question('cf.ech', 65) });
assert.equal(Buffer.from(await unavailable.arrayBuffer()).readUInt16BE(2) & 15, 2, 'missing ECH config must not masquerade as successful fake ECH');
const staticBody = question('cloudflare.com', 1);
const staticPost = await request('/ech', { method:'POST', headers:{'Content-Type':'application/dns-message'}, body:staticBody });
const staticGet = await request('/ech?dns=' + staticBody.toString('base64url'));
assert.deepEqual(Buffer.from(await staticPost.arrayBuffer()), Buffer.from(await staticGet.arrayBuffer()), 'GET and POST use the same static answer path');
assert.equal(staticGet.headers.get('X-Cache'), 'DOH_HIT');
const txt = await request('/api/query?domain=cloudflare.com&type=TXT');
assert.equal(txt.headers.get('Cache-Control'), 'no-store', 'dynamic TXT must not use fixed-address cache');
count = ecsCalls('ech-race.example').length;
await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&ech=ech-race.example&clientIp=192.0.2.123');
assert.ok(ecsCalls('ech-race.example').length > count, 'custom ECH config is isolated by ECS prefix');
count = ecsCalls('ech-race.example').length;
await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&ech=ECH-RACE.EXAMPLE.&clientIp=192.0.2.222');
assert.equal(ecsCalls('ech-race.example').length, count, 'same ECH name and prefix share cached config');
await apiAnswer('cloudflare.com', 'HTTPS', 'enhance=off&ech=ech-race.example&clientIp=192.0.3.1');
assert.ok(ecsCalls('ech-race.example').length > count, 'different ECS prefix must not reuse custom ECH');
// A fast valid answer should need just one upstream, and failure must still reach alternatives.
await apiAnswer('hedge-fast.example', 'A', 'enhance=off');
assert.equal(ecsCalls('hedge-fast.example').length, 1);
assert.ok((await apiAnswer('hedge-failure.example', 'A', 'enhance=off')).answers.length > 0);
assert.ok(ecsCalls('hedge-failure.example').some(c => new URL(c).hostname === 'cloudflare-dns.com'));
const nativeMeta = await apiAnswer('www.facebook.com', 'HTTPS', 'enhance=off');
assert.equal(nativeMeta.ech, 'AAECAw==');
assert.equal(nativeMeta.echSource, 'dns');
assert.ok(nativeMeta.ttl <= 42);
const legacyMeta = await apiAnswer('www.instagram.com', 'HTTPS', 'enhance=off');
assert.equal(legacyMeta.echSource, 'legacy-meta');
assert.ok(legacyMeta.ech && legacyMeta.ttl <= 60);
const fbWire = await wireAnswer('fb.ech', 65, 'enhance=off');
assert.ok(fbWire.readUInt32BE(question('fb.ech',65).length + 6) <= 42);
const cfOwner = await apiAnswer('owner.example','A','enhance=off&best=true&clientIp=192.0.2.1');
assert.ok(cfOwner.answers.includes('104.18.10.118'));
const mixedOwner = await apiAnswer('owner.example','A','enhance=off&best=true&clientIp=192.0.3.1');
assert.deepEqual(mixedOwner.answers, ['104.16.1.1','203.0.113.17']);
const ownerKey = [...cache.keys()].find(k => k.includes('owner-v2:owner.example:') && k.includes('192.0.2.'));
assert.ok(ownerKey, 'owner detection cache must include ECS prefix');
const ownerEntry = await cache.get(ownerKey).clone().json();
assert.ok(ownerEntry.expire - Date.now() <= 20000, 'owner TTL must follow actual DNS');
const nativeThirdParty = await apiAnswer('owner.example','HTTPS','enhance=off&clientIp=192.0.2.1');
assert.equal(nativeThirdParty.echSource, undefined, 'third-party CDN detection must not rewrite default HTTPS');
// AliDNS uses an object instead of an array; ECS fallback retains domestic routing and cache isolation.
assert.deepEqual((await apiAnswer('alidns-object.example.cn','A','enhance=off')).answers,['203.0.113.52']);
const recovered = await apiAnswer('ecs-rejected.example.cn','A','enhance=off&clientIp=192.0.2.15');
assert.deepEqual(recovered.answers,['203.0.113.52']);
const domesticCalls = ecsCalls('ecs-rejected.example.cn').map(c=>new URL(c));
assert.ok(domesticCalls.some(u=>u.searchParams.get('edns_client_subnet')==='192.0.2.0/24'));
assert.ok(domesticCalls.some(u=>!u.searchParams.has('edns_client_subnet')));
assert.ok(domesticCalls.every(u=>['dns.alidns.com','doh.pub'].includes(u.hostname)));
assert.equal((await apiAnswer('wrong-question.example.cn','A','enhance=off')).rcode,2);
// Native direct profile must not apply random IPv6, hosts overrides or forced CDN addresses.
for(const name of ['www.google.com','x.com','api.x.com','pbs.twimg.com','t.co']){
  const a=await apiAnswer(name,'A','enhance=direct&best=true&ip4=1.2.3.4&rules='+encodeURIComponent(name+':1.2.3.4-noA'));
  assert.equal(a.policy,'native-direct');
  assert.deepEqual(a.answers,['203.0.113.17']);
  const v6=await apiAnswer(name,'AAAA','enhance=direct&no6=true');
  assert.deepEqual(v6.answers,['2001:db8::17']);
  const start=calls.length;
  const q=question(name,65);
  const r=await request('/ech?enhance=direct',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:q});
  assert.equal(r.status,200);
  assert.equal(Buffer.from(await r.arrayBuffer()).readUInt16BE(2)&15,0);
  assert.ok(calls.slice(start).some(c=>c==='https://cloudflare-dns.com/dns-query'),'native wire forwarding');
}
assert.equal((await apiAnswer('notgoogle.com','A','enhance=direct')).policy,undefined);
assert.equal((await apiAnswer('x.com.evil.example','A','enhance=direct')).policy,undefined);
assert.deepEqual((await apiAnswer('www.google.com','A','enhance=rule')).answers,[],'legacy Google rule remains opt-in');
assert.equal((await apiAnswer('cloudflare.com','HTTPS','enhance=direct')).policy,undefined);
// Explicit local pins are isolated to exact names and address family, never shared.
const pinParams = 'enhance=direct&pins='+encodeURIComponent('www.google.com=2001:db8::44,2001:db8::45;x.com=203.0.113.88');
const pinned=await apiAnswer('www.google.com','AAAA',pinParams);
assert.deepEqual(pinned.answers,['2001:db8::44','2001:db8::45']);
assert.equal(pinned.policy,'local-pins');
assert.equal(pinned.ttl,30);
assert.deepEqual((await apiAnswer('www.google.com','A',pinParams)).answers,['203.0.113.17']);
assert.deepEqual((await apiAnswer('accounts.google.com','AAAA',pinParams)).answers,['2001:db8::17']);
assert.deepEqual((await apiAnswer('www.google.com','AAAA','enhance=direct')).answers,['2001:db8::17']);
assert.deepEqual((await apiAnswer('x.com','A',pinParams)).answers,['203.0.113.88']);
assert.equal((await apiAnswer('x.com','HTTPS',pinParams)).policy,'native-direct');
const pinPacket=await wireAnswer('www.google.com',28,pinParams);
assert.equal(pinPacket.readUInt16BE(6),2);
assert.equal(pinPacket.readUInt32BE(question('www.google.com',28).length+6),30);
assert.equal(pinPacket.subarray(question('www.google.com',28).length+12,question('www.google.com',28).length+28).toString('hex'),'20010db8000000000000000000000044');
assert.equal((await apiAnswer('www.google.com','AAAA','enhance=direct&pins=www.google.com%3Dinvalid')).policy,'native-direct');
assert.equal((await apiAnswer('example.com','A','enhance=direct&pins=example.com%3D1.2.3.4')).policy,undefined);
// X HTTP/3 experiment: exact host, explicit IP, aligned wire and JSON records.
const xh3='enhance=direct&xh3=172.66.0.227';
const xa=await apiAnswer('x.com','A',xh3);
assert.deepEqual(xa.answers,['172.66.0.227']);
const xhttps=await apiAnswer('x.com','HTTPS',xh3);
assert.equal(xhttps.policy,'x-http3');
assert.equal(xhttps.alpn,'h3,h2');
assert.deepEqual(xhttps.ipv4hints,['172.66.0.227']);
assert.equal(xhttps.ech,null);
assert.equal(xhttps.ttl,30);
const xwire=await wireAnswer('x.com',65,xh3);
assert.equal(xwire.readUInt16BE(6),1);
assert.equal(xwire.readUInt32BE(question('x.com',65).length+6),30);
// Priority 1, root target, alpn=h3,h2, ipv4hint 172.66.0.227, no ECH or no-default-alpn.
assert.equal(xwire.subarray(question('x.com',65).length+12,question('x.com',65).length+33).toString('hex'),'0001000001000602683302683200040004ac4200e3');
assert.deepEqual((await apiAnswer('x.com','A',xh3+'&pins=x.com%3D203.0.113.88')).answers,['172.66.0.227']);
assert.equal((await apiAnswer('api.x.com','HTTPS',xh3)).policy,'native-direct');
assert.equal((await apiAnswer('www.google.com','HTTPS',xh3)).policy,'native-direct');
assert.equal((await apiAnswer('x.com','HTTPS','enhance=direct')).policy,'native-direct');
assert.equal((await apiAnswer('x.com','HTTPS','enhance=direct&xh3=bad')).policy,'native-direct');
assert.equal((await apiAnswer('x.com','HTTPS','enhance=off&xh3=172.66.0.227')).policy,undefined);
// Balanced daily mode preserves complete native responses and routing.
const daily='enhance=balanced';
const wireCalls = () => calls.filter(u=>u.endsWith('/dns-query'));
for (const [name, group] of [['www.taobao.com','domestic'],['www.example.cn','domestic'],['x.com','international'],['www.google.com','international'],['cloudflare.com','international']]) {
  for (const type of [1,28,65,16]) {
    const start=wireCalls().length;
    await wireAnswer(name,type,daily+'&best=true&ip4=1.2.3.4&xh3=172.66.0.227');
    const hosts=wireCalls().slice(start).map(u=>new URL(u).hostname);
    assert.ok(hosts.length>0);
    assert.ok(hosts.every(h=>(group==='domestic'?['dns.alidns.com','doh.pub']:['cloudflare-dns.com','dns.google']).includes(h)), name+' '+type+' '+hosts);
  }
  const value=await apiAnswer(name,'A',daily+'&best=true&ip4=1.2.3.4');
  assert.equal(value.policy,'balanced-'+group);
  assert.deepEqual(value.answers,['203.0.113.17']);
}
const beforeDaily=wireCalls().length;
const dailyEdns=question('www.example.cn',65,{ednsDo:true});
const dailyReply=Buffer.from(await (await request('/ech?'+daily,{method:'POST',headers:{'Content-Type':'application/dns-message'},body:dailyEdns})).arrayBuffer());
assert.equal(dailyReply.readUInt16BE(10),1);
assert.deepEqual(dailyReply.subarray(12),dailyEdns.subarray(12));
assert.ok(wireCalls().slice(beforeDaily).every(u=>['dns.alidns.com','doh.pub'].includes(new URL(u).hostname)));
const beforeFallback=wireCalls().length;
domesticWireOutage=true;
await wireAnswer('www.example.cn',1,daily);
domesticWireOutage=false;
const fallbackHosts=wireCalls().slice(beforeFallback).map(u=>new URL(u).hostname);
assert.ok(fallbackHosts.some(h=>['dns.alidns.com','doh.pub'].includes(h)));
assert.ok(fallbackHosts.some(h=>['cloudflare-dns.com','dns.google'].includes(h)));
assert.equal((await apiAnswer('failure.example.cn','A',daily)).policy,'balanced-fallback');
assert.equal((await apiAnswer('missing.example.cn','A',daily)).rcode,3);
assert.equal((await apiAnswer('missing.example.cn','A',daily)).policy,'balanced-domestic');
const getQuery=question('www.example.cn',1);
const getDaily=await request('/ech?'+daily+'&dns='+getQuery.toString('base64url'));
assert.equal(Buffer.from(await getDaily.arrayBuffer()).readUInt16BE(0),0x1234);
// Domestic ECS is explicit or automatic for mainland clients, and only scoped to domestic A/AAAA/HTTPS.
for(const name of ['www.bilibili.com','p3.douyinpic.com','res.wx.qq.com','img.alicdn.com','api.xiaohongshu.com']){
  assert.equal((await apiAnswer(name,'A',daily)).policy,'balanced-domestic');
}
assert.equal((await apiAnswer('qq.com.evil.example','A',daily)).policy,'balanced-international');
for(const name of ['api.biliapi.net','api.biliapi.com','upos.bilivideo.net','lf.douyinstatic.com','api.snssdk.com','www.tencent.com','res.weixin.com','img.taobaocdn.com','img.jdcdn.com','img.126.net','www.tudou.com']){
  assert.equal((await apiAnswer(name,'A',daily)).policy,'balanced-domestic',name);
  const start=wireBodies.length;
  await wireAnswer(name,1,daily);
  assert.ok(wireBodies.slice(start).length>0);
  assert.ok(wireBodies.slice(start).every(x=>['dns.alidns.com','doh.pub'].includes(x.host)),name);
}
for(const name of ['biliapi.net.example.com','notjdcdn.com','tencent.com.example.com','www.tiktok.com','www.youtube.com']){
  assert.equal((await apiAnswer(name,'A',daily)).policy,'balanced-international',name);
}
const ecsDaily=daily+'&cnEcs=on&clientIp=192.0.2.123';
const original=question('www.taobao.com',1);
let startEcs=wireBodies.length;
const resultEcs=await wireAnswer('www.taobao.com',1,ecsDaily);
let sent=wireBodies.slice(startEcs);
assert.ok(sent.some(x=>x.body.subarray(-11).toString('hex')==='0008000700011800c00002'));
assert.equal(resultEcs.readUInt16BE(10),0,'injected OPT must not leak to stub');
assert.deepEqual(resultEcs.subarray(12),original.subarray(12));
startEcs=wireBodies.length;
await wireAnswer('www.taobao.com',28,daily+'&cnEcs=on&clientIp=2001%3Adb8%3A1234%3A5678%3A%3A1');
assert.ok(wireBodies.slice(startEcs).some(x=>x.body.subarray(-15).toString('hex')==='0008000b0002380020010db8123456'));
for(const [name,type,params] of [['www.google.com',1,ecsDaily],['www.taobao.com',16,ecsDaily],['www.taobao.com',1,daily+'&cnEcs=off&clientIp=192.0.2.123']]){
  const start=wireBodies.length; await wireAnswer(name,type,params);
  assert.ok(wireBodies.slice(start).every(x=>x.body.readUInt16BE(10)===0));
}
const emptyOpt=Buffer.concat([original,Buffer.from([0,0,41,4,208,0,0,0,0,0,0])]);
emptyOpt.writeUInt16BE(1,10);
startEcs=wireBodies.length;
const optResponse=Buffer.from(await (await request('/ech?'+ecsDaily,{method:'POST',headers:{'Content-Type':'application/dns-message'},body:emptyOpt})).arrayBuffer());
assert.ok(wireBodies.slice(startEcs).some(x=>x.body.subarray(-11).toString('hex')==='0008000700011800c00002'));
assert.deepEqual(optResponse.subarray(12),emptyOpt.subarray(12),'client empty OPT retained, injected ECS removed');
const existing=Buffer.concat([emptyOpt,Buffer.from([0,8,0,7,0,1,24,0,198,51,100])]);
existing.writeUInt16BE(11,emptyOpt.length-2);
startEcs=wireBodies.length;
await request('/ech?'+ecsDaily,{method:'POST',headers:{'Content-Type':'application/dns-message'},body:existing});
assert.ok(wireBodies.slice(startEcs).every(x=>x.body.equals(existing)),'existing client ECS untouched');
for(const mode of ['reject','mismatch']){
  ecsReject=mode==='reject';ecsMismatch=mode==='mismatch';startEcs=wireBodies.length;
  const packet=await wireAnswer('www.taobao.com',1,ecsDaily);
  ecsReject=false;ecsMismatch=false;
  assert.equal(packet.readUInt16BE(10),0);
  assert.ok(wireBodies.slice(startEcs).some(x=>x.body.equals(original)),'retry original domestic query after ECS failure');
  assert.ok(wireBodies.slice(startEcs).every(x=>['dns.alidns.com','doh.pub'].includes(x.host)));
}
const autoReq=new Request('https://resolver.example/ech?'+daily,{method:'POST',headers:{'Content-Type':'application/dns-message','CF-Connecting-IP':'192.0.2.123'},body:original});
Object.defineProperty(autoReq,'cf',{value:{country:'CN'}});
startEcs=wireBodies.length;
await worker.fetch(autoReq,env,ctx);
assert.ok(wireBodies.slice(startEcs).some(x=>x.body.subarray(-11).toString('hex')==='0008000700011800c00002'));
const jsonStart=calls.length;
await apiAnswer('www.taobao.com','A',ecsDaily);
assert.ok(calls.slice(jsonStart).some(u=>new URL(u).searchParams.get('edns_client_subnet')==='192.0.2.0/24'));
// HTTPS console preserves alias-mode and all service records, and reports real errors.
const panel=await apiAnswer('https-panel.example','HTTPS','enhance=off');
assert.deepEqual(panel.httpsRecords.map(r=>r.data),['0 svc.example.','1 . alpn=h2,h3']);
assert.equal(panel.ttl,40);
assert.equal((await apiAnswer('https-failure.example','HTTPS','enhance=off')).rcode,2);
assert.equal((await apiAnswer('cloudflare.com','AAAA','enhance=off')).blocked,true);
assert.ok((await apiAnswer('cloudflare.com','HTTPS','enhance=off')).httpsRecords.length);
// Positive domestic cache: TTL aging, transaction IDs, exact question casing, ECS isolation.
const cacheDomain='cache-test.example.cn';
const cacheQuestion=question(cacheDomain,1);
binaryReplyOverride=query=>{
  const end=cacheQuestion.length;
  const reply=Buffer.from(query);
  reply.writeUInt16BE(0x8180,2);reply.writeUInt16BE(1,6);
  const rr=Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,19]);
  return Buffer.concat([reply.subarray(0,end),rr,reply.subarray(end)]);
};
async function cacheReq(params= daily, q=cacheQuestion){
  const r=await request('/ech?'+params,{method:'POST',headers:{'Content-Type':'application/dns-message'},body:q});
  return {hit:r.headers.get('X-Cache'),packet:Buffer.from(await r.arrayBuffer())};
}
let cacheStart=wireBodies.length;
const firstCache=await cacheReq();
assert.equal(firstCache.hit,null);
assert.ok(wireBodies.length>cacheStart);
cacheStart=wireBodies.length;
const changedId=Buffer.from(cacheQuestion);changedId.writeUInt16BE(0x9876,0);
const realNow=Date.now;
Date.now=()=>realNow()+5000;
const hitCache=await cacheReq(daily,changedId);
Date.now=realNow;
assert.equal(hitCache.hit,'DOMESTIC_HIT');
assert.equal(wireBodies.length,cacheStart);
assert.equal(hitCache.packet.readUInt16BE(0),0x9876);
assert.equal(hitCache.packet.readUInt32BE(cacheQuestion.length+6),55);
assert.equal((await cacheReq(daily+'&cnEcs=on&clientIp=192.0.2.123')).hit,null);
assert.equal((await cacheReq(daily+'&cnEcs=on&clientIp=192.0.2.222')).hit,'DOMESTIC_HIT');
assert.equal((await cacheReq(daily+'&cnEcs=on&clientIp=198.51.100.123')).hit,null);
const upper=question('Cache-test.example.cn',1);
assert.equal((await cacheReq(daily,upper)).hit,null);
Date.now=()=>realNow()+61000;
assert.equal((await cacheReq()).hit,null);
Date.now=realNow;
binaryReplyOverride=null;
// Administrator-only metrics reflect actual final responses and cache events.
const auth={headers:{Authorization:'Bearer testsecret'}};
const admin={DOH_ADMIN_TOKEN:'testsecret'};
async function monitor(){const r=await request('/log',auth,admin);assert.equal(r.status,200);assert.equal(r.headers.get('Cache-Control'),'no-store');return (await r.json()).metrics;}
assert.equal((await request('/log',{},admin)).status,404);
assert.equal((await request('/log',auth,{})).status,404);
const shell=await request('/monitor');assert.equal(shell.status,200);assert.equal(shell.headers.get('Cache-Control'),'no-store');
const beforeMetrics=await monitor();
await cacheReq();
simulateBinaryOutage=true;
await request('/doh',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:question('outage.example')});
simulateBinaryOutage=false;
await request('/doh?dns=AA');
const afterMetrics=await monitor();
assert.equal(afterMetrics.scope,'isolate');
assert.equal(afterMetrics.wire.requests-beforeMetrics.wire.requests,3);
assert.equal(afterMetrics.wire.completed-beforeMetrics.wire.completed,3);
assert.equal(afterMetrics.wire.rcode['2']-beforeMetrics.wire.rcode['2'],1);
assert.equal(afterMetrics.wire.httpErrors-beforeMetrics.wire.httpErrors,1);
assert.equal(afterMetrics.cache.domestic.hits-beforeMetrics.cache.domestic.hits,1);
assert.equal(afterMetrics.routing.domestic-beforeMetrics.routing.domestic,1);
assert.ok(afterMetrics.cache.json.hits>0);
assert.ok(afterMetrics.ecs.wireAttempts>0&&afterMetrics.ecs.wireRetries>0);
assert.ok(afterMetrics.upstreams.some(u=>u.failed>0));
assert.ok(!JSON.stringify(afterMetrics).includes(cacheDomain));
// Empty EDNS0 queries get a distinct cache entry; OPT flags are never aged.
const ednsDomain='edns-cache.example.cn', ednsBase=question(ednsDomain,1);
const ednsPlain=Buffer.concat([ednsBase,Buffer.from([0,0,41,4,208,0,0,0,0,0,0])]);
ednsPlain.writeUInt16BE(1,10);
function addressReply(query, questionEnd, code=0, positive=true){
  const reply=Buffer.from(query);reply.writeUInt16BE(0x8180|code,2);
  reply.writeUInt16BE(positive?1:0,6);
  const rr=Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,29]);
  return positive?Buffer.concat([reply.subarray(0,questionEnd),rr,reply.subarray(questionEnd)]):reply;
}
binaryReplyOverride=q=>addressReply(q,ednsBase.length);
const ednsFirst=await cacheReq(daily,ednsPlain);
assert.equal(ednsFirst.hit,null);
assert.equal(ednsFirst.packet.readUInt16BE(10),1);
const ednsId=Buffer.from(ednsPlain);ednsId.writeUInt16BE(0x5678,0);
Date.now=()=>realNow()+5000;
const ednsHit=await cacheReq(daily,ednsId);
Date.now=realNow;
assert.equal(ednsHit.hit,'DOMESTIC_HIT');
assert.equal(ednsHit.packet.readUInt16BE(0),0x5678);
assert.equal(ednsHit.packet.readUInt32BE(ednsBase.length+6),55);
assert.deepEqual(ednsHit.packet.subarray(-11),ednsPlain.subarray(-11));
assert.equal((await cacheReq(daily,ednsBase)).hit,null,'plain query separate from EDNS');
const otherPayload=Buffer.from(ednsPlain);otherPayload.writeUInt16BE(4096,ednsBase.length+3);
assert.equal((await cacheReq(daily,otherPayload)).hit,null,'EDNS UDP size isolated');
const doOpt=Buffer.from(ednsPlain);doOpt.writeUInt16BE(0x8000,ednsBase.length+7);
assert.equal((await cacheReq(daily,doOpt)).hit,null);
assert.equal((await cacheReq(daily,doOpt)).hit,null,'DNSSEC DO bypasses cache');
const cookie=Buffer.concat([ednsPlain,Buffer.from([0,10,0,8,1,2,3,4,5,6,7,8])]);
cookie.writeUInt16BE(12,ednsPlain.length-2);
assert.equal((await cacheReq(daily,cookie)).hit,null);
assert.equal((await cacheReq(daily,cookie)).hit,null,'client EDNS cookie bypasses cache');
const ecsEdns=daily+'&cnEcs=on&clientIp=192.0.2.123';
assert.equal((await cacheReq(ecsEdns,ednsPlain)).hit,null);
assert.equal((await cacheReq(ecsEdns,ednsPlain)).hit,'DOMESTIC_HIT');
assert.equal((await cacheReq(daily+'&cnEcs=on&clientIp=198.51.100.123',ednsPlain)).hit,null);
// A response with its own nonempty EDNS options must not be cached.
const respOptionsDomain=question('response-opt.example.cn',1);
const respOptions=Buffer.concat([respOptionsDomain,ednsPlain.subarray(-11)]);respOptions.writeUInt16BE(1,10);
binaryReplyOverride=q=>{const r=addressReply(q,respOptionsDomain.length);const out=Buffer.concat([r,Buffer.from([0,15,0,2,0,0])]);out.writeUInt16BE(6,r.length-2);return out;};
assert.equal((await cacheReq(daily,respOptions)).hit,null);
assert.equal((await cacheReq(daily,respOptions)).hit,null);
// Domestic address selection waits for a second resolver when the first returns empty/NXDOMAIN.
const qualityDomain=question('quality.example.cn',1);let attempts=0;
binaryReplyOverride=q=>addressReply(q,qualityDomain.length,attempts++===0?3:0,attempts>1);
let quality=await cacheReq(daily,qualityDomain);
assert.equal(quality.packet.readUInt16BE(6),1);
assert.equal(quality.packet.readUInt16BE(2)&15,0);
assert.equal(attempts,2);
const nodataDomain=question('quality-nodata.example.cn',1);attempts=0;
binaryReplyOverride=q=>addressReply(q,nodataDomain.length,attempts++===0?3:0,false);
quality=await cacheReq(daily,nodataDomain);
assert.equal(quality.packet.readUInt16BE(2)&15,0);
assert.equal(quality.packet.readUInt16BE(6),0);
assert.equal(attempts,2);
const missingDomain=question('quality-missing.example.cn',1);attempts=0;
binaryReplyOverride=q=>{attempts++;return addressReply(q,missingDomain.length,3,false);};
quality=await cacheReq(daily,missingDomain);
assert.equal(quality.packet.readUInt16BE(2)&15,3);
assert.equal(attempts,2,'valid NXDOMAIN does not trigger international fallback');
// Truncation and EDNS extended errors are failed attempts, not usable address answers.
const truncatedDomain=question('quality-truncated.example.cn',1);attempts=0;
binaryReplyOverride=q=>{
  const p=addressReply(q,truncatedDomain.length);
  if(attempts++===0)p.writeUInt16BE(0x8380,2);
  return p;
};
quality=await cacheReq(daily,truncatedDomain);
assert.equal(quality.packet.readUInt16BE(2)&0x0200,0);
assert.equal(quality.packet.readUInt16BE(6),1);
assert.equal(attempts,2);
const badversBase=question('quality-badvers.example.cn',1);
const badversQuery=Buffer.concat([badversBase,ednsPlain.subarray(-11)]);
badversQuery.writeUInt16BE(1,10);attempts=0;
binaryReplyOverride=q=>{
  const p=addressReply(q,badversBase.length);
  if(attempts++===0)p.writeUInt32BE(0x01000000,p.length-6);
  return p;
};
quality=await cacheReq(daily,badversQuery);
assert.equal(quality.packet.readUInt32BE(quality.packet.length-6),0);
assert.equal(attempts,2);
const fallbackDomain=question('quality-truncated-fallback.example.cn',1);attempts=0;
const routingBefore=(await monitor()).routing.fallback;
binaryReplyOverride=q=>{
  const p=addressReply(q,fallbackDomain.length);
  if(attempts++<2)p.writeUInt16BE(0x8380,2);
  return p;
};
quality=await cacheReq(daily,fallbackDomain);
assert.equal(quality.packet.readUInt16BE(2)&0x0200,0);
assert.equal(quality.packet.readUInt16BE(6),1);
assert.equal(attempts,3);
assert.equal((await monitor()).routing.fallback-routingBefore,1);
const allTruncated=question('quality-all-truncated.example.cn',1);attempts=0;
binaryReplyOverride=q=>{
  attempts++;const p=addressReply(q,allTruncated.length);
  p.writeUInt16BE(0x8380,2);return p;
};
quality=await cacheReq(daily,allTruncated);
assert.equal(quality.packet.readUInt16BE(2)&15,2);
assert.equal(attempts,4);
// International balanced A/AAAA uses a separate native positive cache without ECS injection.
const intlBase=question('cache-international.example.com',1);
const intlQuery=Buffer.concat([intlBase,ednsPlain.subarray(-11)]);intlQuery.writeUInt16BE(1,10);
const intlMetricsBefore=(await monitor()).cache.international;
binaryReplyOverride=q=>addressReply(q,intlBase.length);
let intlStart=wireBodies.length;
const intlFirst=await cacheReq(daily+'&cnEcs=on&clientIp=192.0.2.123',intlQuery);
assert.equal(intlFirst.hit,null);
assert.ok(wireBodies.length>intlStart);
assert.ok(wireBodies.slice(intlStart).every(x=>['cloudflare-dns.com','dns.google'].includes(x.host)&&x.body.equals(intlQuery)));
intlStart=wireBodies.length;
const intlId=Buffer.from(intlQuery);intlId.writeUInt16BE(0x4567,0);
Date.now=()=>realNow()+5000;
const intlHit=await cacheReq(daily+'&cnEcs=on&clientIp=198.51.100.123',intlId);
Date.now=realNow;
assert.equal(intlHit.hit,'INTERNATIONAL_HIT');
assert.equal(wireBodies.length,intlStart);
assert.equal(intlHit.packet.readUInt16BE(0),0x4567);
assert.equal(intlHit.packet.readUInt32BE(intlBase.length+6),55);
assert.deepEqual(intlHit.packet.subarray(-11),intlQuery.subarray(-11));
assert.equal((await cacheReq(daily,intlBase)).hit,null);
const intlDo=Buffer.from(intlQuery);intlDo.writeUInt16BE(0x8000,intlQuery.length-4);
assert.equal((await cacheReq(daily,intlDo)).hit,null);
assert.equal((await cacheReq(daily,intlDo)).hit,null);
const intlMetricsAfter=(await monitor()).cache.international;
assert.equal(intlMetricsAfter.hits-intlMetricsBefore.hits,1);
assert.equal(intlMetricsAfter.misses-intlMetricsBefore.misses,2);
assert.equal(intlMetricsAfter.bypasses-intlMetricsBefore.bypasses,2);
const intlNegative=question('cache-negative.example.com',1);
binaryReplyOverride=q=>addressReply(q,intlNegative.length,3,false);
assert.equal((await cacheReq(daily,intlNegative)).hit,null);
assert.equal((await cacheReq(daily,intlNegative)).hit,null);
// Native HTTPS replies retain their original wire records and recover from NODATA/TC.
const nativeHttps=question('native-quality.example.com',65);
const nativeRR=Buffer.from([0xc0,0x0c,0,65,0,1,0,0,0,60,0,3,0,1,0]);
attempts=0;
binaryReplyOverride=q=>{
  const p=Buffer.from(q);p.writeUInt16BE(0x8180,2);
  if(attempts++===0)return p;
  p.writeUInt16BE(1,6);return Buffer.concat([p,nativeRR]);
};
let nativeResult=await cacheReq(daily,nativeHttps);
assert.equal(attempts,2);
assert.deepEqual(nativeResult.packet.subarray(nativeHttps.length),nativeRR);
assert.equal(nativeResult.hit,null);
attempts=0;
binaryReplyOverride=q=>{
  const p=Buffer.from(q);p.writeUInt16BE(attempts++===0?0x8380:0x8180,2);
  p.writeUInt16BE(1,6);return Buffer.concat([p,nativeRR]);
};
const nativeTc=question('native-tc.example.com',65);
nativeResult=await cacheReq(daily,nativeTc);
assert.equal(attempts,2);
assert.equal(nativeResult.packet.readUInt16BE(2)&0x0200,0);
assert.deepEqual(nativeResult.packet.subarray(nativeTc.length),nativeRR);
assert.equal(nativeResult.hit,null);
const nativeCached=await cacheReq(daily,nativeHttps);
assert.equal(nativeCached.hit,'INTERNATIONAL_HIT');
assert.deepEqual(nativeCached.packet.subarray(nativeHttps.length),nativeRR);
Date.now=()=>realNow()+61000;
assert.equal((await cacheReq(daily,nativeHttps)).hit,null);
Date.now=realNow;
binaryReplyOverride=null;
// An incompatible ECS answer must not win over another compatible domestic resolver.
const ecsRaceBase=question('ecs-race.example.cn',1);
let ecsRaceAttempts=0;
binaryReplyOverride=q=>{
  const p=addressReply(q,ecsRaceBase.length);
  if(ecsRaceAttempts++===0)p[p.length-1]^=1;
  return p;
};
const ecsRaceBefore=(await monitor()).ecs;
const ecsRaceStart=wireBodies.length;
const ecsRaceResult=await cacheReq(daily+'&cnEcs=on&clientIp=192.0.2.123',ecsRaceBase);
assert.equal(ecsRaceResult.packet.readUInt16BE(6),1);
assert.equal(ecsRaceResult.packet.readUInt16BE(10),0);
assert.equal(ecsRaceAttempts,2);
assert.ok(wireBodies.slice(ecsRaceStart).every(x=>x.body.length>ecsRaceBase.length));
const ecsRaceAfter=(await monitor()).ecs;
assert.equal(ecsRaceAfter.wireAccepted-ecsRaceBefore.wireAccepted,1);
assert.equal(ecsRaceAfter.wireRetries-ecsRaceBefore.wireRetries,0);
binaryReplyOverride=null;
// Pure forwarding preserves extended RCODEs; monitoring must not count BADVERS as NOERROR.
const monitorBase=question('monitor-badvers.example.com',1);
const monitorQuery=Buffer.concat([monitorBase,ednsPlain.subarray(-11)]);
monitorQuery.writeUInt16BE(1,10);
const monitorBefore=(await monitor()).wire.rcode;
binaryReplyOverride=q=>{
  const p=addressReply(q,monitorBase.length,0,false);
  p.writeUInt32BE(0x01000000,p.length-6);
  return p;
};
const monitorReply=await request('/doh',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:monitorQuery});
assert.equal(Buffer.from(await monitorReply.arrayBuffer()).readUInt32BE(monitorQuery.length-6),0x01000000);
const monitorAfter=(await monitor()).wire.rcode;
assert.equal((monitorAfter['16']||0)-(monitorBefore['16']||0),1);
assert.equal((monitorAfter['0']||0)-(monitorBefore['0']||0),0);
binaryReplyOverride=null;
// Keep hot entries through capacity pressure without extending their original TTL.
const lruHot=question('lru-hot.example.com',1);
const lruCold=question('lru-cold.example.com',1);
binaryReplyOverride=q=>addressReply(q,q.length);
assert.equal((await cacheReq(daily,lruHot)).hit,null);
assert.equal((await cacheReq(daily,lruCold)).hit,null);
for(let i=0;i<510;i++) await cacheReq(daily,question('lru-'+i+'.example.com',1));
assert.equal((await cacheReq(daily,lruHot)).hit,'INTERNATIONAL_HIT');
await cacheReq(daily,question('lru-overflow.example.com',1));
assert.equal((await cacheReq(daily,lruHot)).hit,'INTERNATIONAL_HIT');
assert.equal((await cacheReq(daily,lruCold)).hit,null);
Date.now=()=>realNow()+61000;
assert.equal((await cacheReq(daily,lruHot)).hit,null);
Date.now=realNow;
binaryReplyOverride=null;
console.log('Doh-ECH smoke tests passed (including adaptive upstreams, Meta ECH, owner TTL and ECS)');
