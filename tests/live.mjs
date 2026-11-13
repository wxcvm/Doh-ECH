import assert from 'node:assert/strict';

const base = process.env.DOH_ECH_TEST_URL;
if (!base) throw new Error('Set DOH_ECH_TEST_URL to the deployed test Worker');
const endpoint = new URL(base);
assert.equal(endpoint.protocol, 'https:', 'Use HTTPS for live DoH checks');

let passed = 0;
async function check(name, fn) {
  const start = Date.now();
  await fn();
  passed++;
  console.log('PASS ' + name + ' (' + (Date.now() - start) + ' ms)');
}
async function fetchEndpoint(path, init = {}) {
  return fetch(new URL(path, endpoint), { ...init, signal: AbortSignal.timeout(15000) });
}
async function api(name, type, params = {}) {
  const query = new URLSearchParams({ domain: name, type, ...params });
  const r = await fetchEndpoint('/api/query?' + query);
  assert.equal(r.status, 200, name + ': JSON HTTP status');
  const result = await r.json();
  assert.ok(Array.isArray(result.answers), name + ': missing answers');
  assert.ok(!result.error, name + ': ' + result.error);
  assert.ok(result.rcode === undefined || result.rcode === 0, name + ': DNS RCODE ' + result.rcode);
  return result;
}
function question(name, type = 1) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x6a41, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const labels = name.split('.').flatMap(label => [Buffer.from([label.length]), Buffer.from(label)]);
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(type, 1);
  tail.writeUInt16BE(1, 3);
  return Buffer.concat([header, ...labels, tail]);
}
async function wire(path, name, type, method = 'POST', params = {}, expectedRcode = 0) {
  const body = question(name, type);
  const query = new URLSearchParams(params);
  if (method === 'GET') query.set('dns', body.toString('base64url'));
  const response = await fetchEndpoint(path + '?' + query, {
    method,
    headers: method === 'POST' ? { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' } : { Accept: 'application/dns-message' },
    ...(method === 'POST' ? { body } : {})
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type') || '', /^application\/dns-message/i);
  const data = Buffer.from(await response.arrayBuffer());
  assert.ok(data.length >= body.length, 'DNS reply truncated');
  assert.equal(data.readUInt16BE(0), 0x6a41, 'transaction ID mismatch');
  assert.equal(data.readUInt16BE(2) & 0x8000, 0x8000, 'not a DNS response');
  assert.equal(data.readUInt16BE(2) & 15, expectedRcode, 'DNS RCODE');
  assert.equal(data.readUInt16BE(4), 1, 'question count');
  assert.deepEqual(data.subarray(12, body.length), body.subarray(12), 'question mismatch');
  return data;
}

await check('real upstream A via /doh GET and POST', async () => {
  for (const method of ['GET', 'POST']) assert.ok((await wire('/doh', 'example.com', 1, method)).readUInt16BE(6) > 0);
});
await check('FCM IPv4 preserved with opt-in rules', async () => {
  const result = await api('mtalk.google.com', 'A', { enhance: 'rule' });
  assert.ok(result.answers.length > 0, 'FCM A must not be suppressed');
  assert.ok((await wire('/ech', 'mtalk.google.com', 1, 'POST', { enhance: 'rule' })).readUInt16BE(6) > 0);
  const v6 = await api('mtalk.google.com', 'AAAA', { enhance: 'rule' });
  console.log('FCM actual AAAA answer count: ' + v6.answers.length + ' (upstream-dependent)');
});
await check('Google regional rule and wire response', async () => {
  const result = await api('google.co.jp', 'A', { enhance: 'rule' });
  assert.deepEqual(result.answers, []);
  const v6 = await api('google.co.jp', 'AAAA', { enhance: 'rule' });
  assert.ok(v6.answers.length > 0 && v6.answers.every(ip => ip.startsWith('2001:4860:')));
  assert.equal((await wire('/ech', 'google.co.jp', 1, 'POST', { enhance: 'rule' })).readUInt16BE(6), 0);
});
await check('dl.google.com IPv4-only policy and HTTPS hints', async () => {
  assert.ok((await api('dl.google.com', 'A', { enhance: 'rule' })).answers.length > 0);
  assert.deepEqual((await api('dl.google.com', 'AAAA', { enhance: 'rule' })).answers, []);
  assert.equal((await wire('/ech', 'dl.google.com', 28, 'POST', { enhance: 'rule' })).readUInt16BE(6), 0);
  const https = await api('dl.google.com', 'HTTPS', { enhance: 'rule' });
  assert.ok(https.ipv4hints?.length > 0, 'missing IPv4 hints');
  assert.ok(!https.ipv6hints?.length, 'unexpected IPv6 hints');
});
await check('Cloudflare AAAA explicit opt-in and default suppression', async () => {
  assert.deepEqual((await api('cloudflare.com', 'AAAA')).answers, []);
  assert.ok((await api('cloudflare.com', 'AAAA', { nocf6: 'false' })).answers.length > 0);
});
await check('public log remains private and malformed DoH rejected', async () => {
  assert.equal((await fetchEndpoint('/log')).status, 404);
  assert.equal((await fetchEndpoint('/doh?dns=AA')).status, 400);
});
await check('real A TTL and ECS-compatible requests', async () => {
  for (const clientIp of ['192.0.2.123', '192.0.2.222', '2001:db8:abcd:12ff::42']) {
    const result = await api('example.com', 'A', { enhance: 'off', clientIp });
    assert.ok(result.answers.length > 0);
    assert.ok(Number.isInteger(result.ttl) && result.ttl >= 0 && result.ttl <= 300, 'invalid TTL');
  }
  const response = await fetchEndpoint('/api/query?domain=example.com&type=A&enhance=off&clientIp=192.0.2.123');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const packet = await wire('/ech', 'example.com', 1, 'POST', { enhance: 'off', clientIp: '192.0.2.123' });
  assert.ok(packet.readUInt16BE(6) > 0);
  assert.ok(packet.readUInt32BE(question('example.com').length + 6) <= 300);
});
await check('NXDOMAIN preserved in JSON and wire DNS', async () => {
  const name = 'nonexistent-doh-ech.invalid';
  const response = await fetchEndpoint('/api/query?domain=' + name + '&type=A&enhance=off');
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.rcode, 3);
  assert.deepEqual(result.answers, []);
  assert.equal((await wire('/ech', name, 1, 'POST', { enhance: 'off' }, 3)).readUInt16BE(6), 0);
});
console.log('All ' + passed + ' live Worker checks passed; this verifies DNS behavior, not end-to-end ECH/TLS connectivity.');
