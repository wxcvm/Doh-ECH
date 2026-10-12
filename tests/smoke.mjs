import assert from 'node:assert/strict';
import worker from '../_worker.js';

// Lightweight Cloudflare runtime mocks. Tests must not perform network requests.
const calls = [];
const cache = new Map();
globalThis.caches = {
  default: {
    async match(key) { return cache.get(String(key))?.clone() || undefined; },
    async put(key, response) { cache.set(String(key), response.clone()); }
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
    const reply = Buffer.from(init.body);
    if (reply.length < 12) throw new Error('Invalid test query');
    reply.writeUInt16BE(0x8180, 2);
    reply.writeUInt16BE(0, 6);
    reply.writeUInt16BE(0, 8);
    reply.writeUInt16BE(0, 10);
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
assert.ok(record.answers?.includes('203.0.113.17'), 'non-Cloudflare domain must retain upstream A answers: '+JSON.stringify({record,calls:calls.filter(s=>s.includes('github.com'))}));

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

console.log('Doh-ECH smoke tests passed');
