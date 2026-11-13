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
await check('real ECH bootstrap and synthesized HTTPS TTL', async () => {
  const native = await api('cloudflare-ech.com', 'HTTPS', { enhance: 'off' });
  const configured = await api('cloudflare.com', 'HTTPS', { enhance: 'off' });
  assert.ok(configured.ech, 'Cloudflare ECH config must be present');
  assert.ok(Number.isInteger(configured.ttl) && configured.ttl >= 0 && configured.ttl <= 300);
  for (const name of ['cloudflare.com', 'cf.ech']) {
    for (const method of ['GET', 'POST']) {
      const packet = await wire('/ech', name, 65, method, { enhance: 'off' });
      assert.equal(packet.readUInt16BE(6), 1, name + ': expected HTTPS record');
      assert.ok(packet.readUInt32BE(question(name, 65).length + 6) <= 300, name + ': excessive TTL');
    }
  }
  console.log('Native ECH query: ' + (native.ech ? 'config exposed' : 'no JSON ECH field') + '; synthesized TTL: ' + configured.ttl);
});
await check('Meta ECH DNS response and compatibility alias', async () => {
  for (const name of ['www.facebook.com', 'www.instagram.com']) {
    const result = await api(name, 'HTTPS', { enhance: 'off' });
    assert.ok(result.ech, name + ': no ECH config');
    assert.ok(['dns', 'legacy-meta'].includes(result.echSource), name + ': ECH source missing');
    assert.ok(result.ttl >= 0 && result.ttl <= (result.echSource === 'legacy-meta' ? 30 : 300));
    console.log(name + ': ECH source ' + result.echSource + ', TTL ' + result.ttl);
    const packet = await wire('/ech', name, 65, 'POST', { enhance: 'off' });
    assert.equal(packet.readUInt16BE(6), 1);
  }
  const alias = await wire('/ech', 'fb.ech', 65, 'GET', { enhance: 'off' });
  assert.equal(alias.readUInt16BE(6), 1);
  assert.ok(alias.readUInt32BE(question('fb.ech', 65).length + 6) <= 300);
});
await check('ordinary domain retains native HTTPS policy', async () => {
  const result = await api('example.com', 'HTTPS', { enhance: 'off' });
  assert.equal(result.echSource, undefined);
});
await check('balanced domestic routing and real wire ECS compatibility', async () => {
  for(const domain of ['www.taobao.com','www.bilibili.com','www.baidu.com','www.jd.com','www.douyin.com']){
    const options={enhance:'balanced',cnEcs:'on',clientIp:'223.5.5.5'};
    const result=await api(domain,'A',options);
    assert.equal(result.policy,'balanced-domestic');
    assert.ok(result.answers.length>0,domain+' A');
    const plain=await api(domain,'A',{enhance:'balanced',cnEcs:'off'});
    assert.ok(plain.answers.length>0,domain+' A without added ECS');
    const packet=await wire('/ech',domain,1,'POST',options);
    assert.ok(packet.readUInt16BE(6)>0);
    // Original test query has no OPT; injected ECS must not leak to the client.
    assert.equal(packet.readUInt16BE(10),0);
    console.log(domain+' domestic A: '+result.answers.join(',')+'; no ECS: '+plain.answers.join(',')+'; TTL '+result.ttl);
  }
  for(const type of [28,65]) await wire('/ech','www.taobao.com',type,'GET',{enhance:'balanced',cnEcs:'on',clientIp:'223.5.5.5'});
  assert.equal((await api('www.google.com','A',{enhance:'balanced',cnEcs:'on',clientIp:'223.5.5.5'})).policy,'balanced-international');
});
await check('domestic empty EDNS0 A queries and cache observations', async()=>{
  const name='www.baidu.com',baseQuestion=question(name,1);
  let hits=0;
  for(let i=0;i<3;i++){
    const body=Buffer.concat([baseQuestion,Buffer.from([0,0,41,4,208,0,0,0,0,0,0])]);
    body.writeUInt16BE(1,10);body.writeUInt16BE(0x6a41+i,0);
    const start=Date.now();
    const response=await fetchEndpoint('/ech?enhance=balanced&cnEcs=off',{
      method:'POST',headers:{'Content-Type':'application/dns-message'},body
    });
    assert.equal(response.status,200);
    const packet=Buffer.from(await response.arrayBuffer());
    assert.equal(packet.readUInt16BE(0),0x6a41+i);
    assert.equal(packet.readUInt16BE(2)&15,0);
    assert.equal(packet.readUInt16BE(4),1);
    assert.ok(packet.readUInt16BE(6)>0);
    assert.deepEqual(packet.subarray(12,baseQuestion.length),baseQuestion.subarray(12));
    const cache=response.headers.get('X-Cache')||'not-hit';
    if(cache==='DOMESTIC_HIT')hits++;
    console.log('Domestic EDNS sample '+(i+1)+': '+cache+' '+(Date.now()-start)+' ms');
  }
  console.log('Domestic EDNS observed cache hits: '+hits+'/3 (isolate-local; not a guaranteed hit rate)');
});
console.log('All ' + passed + ' live Worker checks passed; this verifies DNS behavior, not end-to-end ECH/TLS connectivity.');
