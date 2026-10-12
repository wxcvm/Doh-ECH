import assert from 'node:assert/strict';
import worker from '../_worker.js';

// Lightweight Cloudflare runtime mocks. Tests must not perform network requests.
const calls = [];
const cache = new Map();
let simulateBinaryOutage = false;
let binaryReplyOverride = null;
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
    if (simulateBinaryOutage) return new Response('temporarily unavailable', { status: 503 });
    if (binaryReplyOverride) {
      return new Response(binaryReplyOverride(Buffer.from(init.body)), {
        headers: { 'Content-Type': 'application/dns-message' }
      });
    }
    if (url.hostname === 'dns.alidns.com') {
      return new Response('not a DNS response', { headers: { 'Content-Type': 'text/html' } });
    }
    const reply = Buffer.from(init.body);
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
    return Response.json({
      Status: error ? 2 : 0,
      Question: [{ name: name + '.', type }],
      Answer: error ? [] : (type === 1 ? [{ name, type, TTL: 300, data: '203.0.113.17' }] : [])
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

console.log('Doh-ECH smoke tests passed (EDNS outage and 11 malformed upstream regressions included)');
