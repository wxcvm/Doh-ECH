import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const base = process.env.DOH_ECH_TEST_URL;
if (!base) throw new Error('DOH_ECH_TEST_URL is required');
const browser = await chromium.launch({headless:true, channel:'chrome'});
try {
  const context = await browser.newContext({viewport:{width:390,height:844},reducedMotion:'reduce',permissions:['clipboard-read','clipboard-write']});
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(base, {waitUntil:'domcontentloaded'});
  await page.locator('#queryForm').waitFor();
  assert.equal(await page.locator('.preset').count(),8);
  assert.equal(await page.locator('#advanced').evaluate(e=>e.open),false);
  assert.equal(await page.locator('#dohUrl').textContent(),new URL('/doh',base).href);
  assert.equal(await page.locator('#echUrl').textContent(),new URL('/ech',base).href);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  console.log('PASS mobile layout and default addresses');

  await page.getByRole('button',{name:'普通 DNS',exact:false}).click();
  await page.locator('#cards .result-card').last().waitFor();
  await page.waitForFunction(()=>document.querySelector('#cards').children.length===3 && !document.querySelector('#queryBtn').disabled);
  assert.equal(await page.locator('#cards .result-card').count(),3);
  assert.match(await page.locator('[data-type=A] .status').textContent(),/已返回记录/);
  assert.match(await page.locator('#resultSummary').textContent(),/github.com/);
  await page.locator('.raw summary').click();
  assert.equal(JSON.parse(await page.locator('#rawJson').textContent()).length,3);
  await page.waitForFunction(()=>document.getElementById('results').getBoundingClientRect().top<innerHeight);
  console.log('PASS real DNS batch query and raw JSON');

  await page.getByRole('button',{name:'Cloudflare ECH',exact:false}).click();
  await page.locator('#cards [data-type=HTTPS] .status').filter({hasText:'已取得 ECH 配置'}).waitFor();
  console.log('PASS real ECH result');

  await page.getByRole('button',{name:'Meta ECH',exact:false}).click();
  await page.locator('#cards [data-type=HTTPS] .status').filter({hasText:'已取得 ECH 配置'}).waitFor();
  assert.match(await page.locator('#cards').textContent(),/ECH 来源/);
  await page.getByRole('button',{name:'Android 推送',exact:false}).click();
  await page.locator('#cards [data-type=A] .status').filter({hasText:'已返回记录'}).waitFor();
  assert.match(await page.locator('#resultSummary').textContent(),/mtalk.google.com/);
  // Real domestic queries must remain usable with valid ECS and automatic client IP.
  for(const name of ['taobao.com','www.baidu.com']){
    const response=await page.request.get(new URL('/api/query?domain='+name+'&type=A&clientIp=114.114.114.114',base).href);
    const data=await response.json();
    assert.equal(data.rcode,0,name+' ECS resolution failed: '+JSON.stringify(data));
    assert.ok(data.answers.length>0,name+' must return A records');
  }
  await page.getByRole('button',{name:'国内解析',exact:false}).click();
  await page.locator('#cards [data-type=A] .status').filter({hasText:'已返回记录'}).waitFor();
  assert.match(await page.locator('#cards [data-type=A] .status').textContent(),/已返回记录/);
  assert.match(await page.locator('#resultSummary').textContent(),/taobao.com/);
  console.log('PASS real Meta, Android FCM and domestic presets');

  await page.getByRole('button',{name:'Google IPv6',exact:false}).click();
  await page.locator('#cards [data-type=AAAA] .status').filter({hasText:'已返回记录'}).waitFor();
  assert.equal(await page.locator('#echUrl').textContent(),new URL('/ech?enhance=rule',base).href);
  await page.locator('[data-copy=echUrl]').click();
  await page.locator('#copyStatus').filter({hasText:'已复制'}).waitFor();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),new URL('/ech?enhance=rule',base).href);
  console.log('PASS real Google IPv6 preset and clipboard');

  for(const [label,domain] of [['Google 直连诊断','www.google.com'],['X 直连诊断','x.com']]){
    await page.getByRole('button',{name:label,exact:false}).click();
    await page.locator('#cards .result-card').last().waitFor();
    await page.waitForFunction(()=>document.querySelector('#cards').children.length===3 && !document.querySelector('#queryBtn').disabled);
    const raw=JSON.parse(await page.locator('#rawJson').textContent());
    assert.equal(raw[0].policy,'native-direct');
    assert.equal(raw[0].rcode,0,JSON.stringify(raw[0]));
    assert.ok(raw[0].answers.length>0);
    assert.equal(raw[0].domain,domain);
    assert.match(await page.locator('#echUrl').textContent(),/enhance=direct/);
    console.log('PASS native direct '+domain+' A='+raw[0].answers.length+' AAAA='+raw[1].answers.length+' ECH='+Boolean(raw[2].ech));
  }
  // Local pins must be explicit, copied into the URL and reflected in real DNS JSON.
  await page.locator('#advanced summary').click();
  await page.locator('#pins').fill('x.com=203.0.113.88');
  await page.locator('#type').selectOption('A');
  await page.locator('#queryBtn').click();
  await page.locator('#cards [data-type=A]').filter({hasText:'203.0.113.88'}).waitFor();
  const pinned=JSON.parse(await page.locator('#rawJson').textContent())[0];
  assert.equal(pinned.policy,'local-pins');
  assert.equal(pinned.ttl,30);
  assert.equal(new URL(await page.locator('#echUrl').textContent()).searchParams.get('pins'),'x.com=203.0.113.88');
  console.log('PASS local pin input, real DNS response and generated URL');

  // Daily balanced profile exposes native DNS, with a separate ready-to-copy URL.
  assert.equal(await page.locator('#balancedUrl').textContent(),new URL('/ech?enhance=balanced',base).href);
  await page.locator('#enhance').selectOption('balanced');
  await page.locator('#domain').fill('www.taobao.com');
  await page.locator('#type').selectOption('A');
  await page.locator('#queryBtn').click();
  await page.locator('#cards [data-type=A]').filter({hasText:'日常均衡 · 国内上游'}).waitFor();
  assert.equal(new URL(await page.locator('#echUrl').textContent()).searchParams.toString(),'enhance=balanced');
  await page.getByRole('button',{name:'X 直连诊断',exact:false}).click();
  await page.locator('#cards [data-type=HTTPS]').waitFor();
  await page.waitForFunction(()=>!document.querySelector('#queryBtn').disabled);
  await page.locator('#advanced summary').click();
  console.log('PASS daily balanced preset and native domestic route');

  // Explicit QUIC profile must expose the same address in A and HTTPS hints.
  await page.locator('#pins').fill('');
  await page.locator('#xh3').fill('172.66.0.227');
  await page.locator('#type').selectOption('all');
  await page.locator('#queryBtn').click();
  await page.locator('#cards [data-type=HTTPS] .status').filter({hasText:'已声明 HTTP/3'}).waitFor();
  await page.waitForFunction(()=>!document.querySelector('#queryBtn').disabled);
  const h3=JSON.parse(await page.locator('#rawJson').textContent());
  assert.deepEqual(h3[0].answers,['172.66.0.227']);
  assert.equal(h3[2].policy,'x-http3');
  assert.equal(h3[2].alpn,'h3,h2');
  assert.deepEqual(h3[2].ipv4hints,['172.66.0.227']);
  assert.equal(new URL(await page.locator('#echUrl').textContent()).searchParams.get('xh3'),'172.66.0.227');
  console.log('PASS X HTTP/3 profile, address consistency and generated URL');

  // A fast panel must display before a delayed HTTPS query finishes.
  let releaseHttps;
  const httpsGate=new Promise(resolve=>{releaseHttps=resolve;});
  await page.route('**/api/query?*',async route=>{
    const u=new URL(route.request().url()),type=u.searchParams.get('type'),domain=u.searchParams.get('domain');
    if(type==='HTTPS')await httpsGate;
    const data={domain,type,answers:type==='A'?['203.0.113.42']:[],rcode:0,ttl:60};
    if(type==='HTTPS')data.httpsRecords=[{name:domain,ttl:60,data:'0 svc.example.'}];
    await route.fulfill({json:data});
  });
  await page.locator('#domain').fill('example.com');
  await page.locator('#type').selectOption('all');
  await page.locator('#queryBtn').click();
  await page.locator('#cards [data-type=A] .status').filter({hasText:'已返回记录'}).waitFor();
  assert.match(await page.locator('#cards [data-type=HTTPS] .status').textContent(),/查询中/);
  await page.locator('#cards [data-type=AAAA] .status').filter({hasText:'无此类记录'}).waitFor();
  releaseHttps();
  await page.locator('#cards [data-type=HTTPS] .status').filter({hasText:'已返回 HTTPS 记录'}).waitFor();
  assert.match(await page.locator('#cards [data-type=HTTPS]').textContent(),/0 svc.example\./);
  await page.waitForFunction(()=>!document.querySelector('#queryBtn').disabled);
  await page.unroute('**/api/query?*');
  console.log('PASS independent panels, NODATA, and native HTTPS alias record');

  // Restore the rule preset before checking its advanced parameters.
  await page.getByRole('button',{name:'Google IPv6',exact:false}).click();
  await page.locator('#cards [data-type=AAAA] .status').filter({hasText:'已返回记录'}).waitFor();

  // Deterministic UI edge cases: validate exact query URL and safe text rendering.
  await page.route('**/api/query?*',async route=>{
    const u=new URL(route.request().url());
    assert.equal(u.searchParams.get('domain'),'example.com');
    assert.equal(u.searchParams.get('type'),'AAAA');
    assert.equal(u.searchParams.get('enhance'),'rule');
    assert.equal(u.searchParams.get('nocf6'),'false');
    assert.equal(u.searchParams.get('clientIp'),'192.0.2.1');
    await route.fulfill({json:{domain:'example.com',type:'AAAA',answers:[],rcode:3}});
  });
  await page.locator('#advanced summary').click();
  await page.locator('#allowCF6').check();
  await page.locator('#clientIp').fill('192.0.2.1');
  await page.locator('#domain').fill('https://example.com/path');
  await page.locator('#queryBtn').click();
  await page.locator('#cards .status').filter({hasText:'域名不存在'}).waitFor();
  assert.match(await page.locator('#echUrl').textContent(),/nocf6=false/);
  assert.match(await page.locator('#echUrl').textContent(),/clientIp=192.0.2.1/);
  console.log('PASS advanced parameter parity, URL normalization and NXDOMAIN status');
  await page.unroute('**/api/query?*');
  await page.route('**/api/query?*',route=>route.fulfill({status:500,json:{error:'<img src=x onerror=alert(1)> test'}}));
  await page.locator('#queryBtn').click();
  await page.locator('#cards .status').filter({hasText:'查询失败'}).waitFor();
  assert.equal(await page.locator('#cards img').count(),0);
  assert.match(await page.locator('#cards').textContent(),/<img src=x/);
  console.log('PASS error display uses safe text');
  await page.unroute('**/api/query?*');
  await page.locator('#resetBtn').click();
  assert.equal(await page.locator('#advanced').evaluate(e=>e.open),false);
  assert.equal(await page.locator('#echUrl').textContent(),new URL('/ech',base).href);
  assert.equal(await page.locator('#results').isVisible(),false);
  await page.setViewportSize({width:1280,height:900});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  assert.equal(errors.length,0,errors.join('\n'));
  console.log('PASS reset, desktop layout, no browser JavaScript errors');
  // Monitor shell is public, data requires the existing private token.
  await page.goto(new URL('/monitor',base).href);
  assert.equal(await page.locator('#stats').isVisible(),false);
  await page.locator('#token').fill('not-a-real-token');
  await page.locator('#refresh').click();
  await page.locator('#status').filter({hasText:'令牌不正确'}).waitFor();
  await page.route('**/log',async route=>{
    assert.equal(route.request().headers().authorization,'Bearer testsecret');
    await route.fulfill({json:{metrics:{scope:'isolate',startedAt:'start',updatedAt:'now',
      wire:{requests:3,completed:3,rcode:{'0':2,'2':1},httpErrors:0,exceptions:0,avgMs:12},
      routing:{domestic:2,international:1,domesticAvgMs:10,internationalAvgMs:16,fallback:0},
      cache:{domestic:{hits:1,misses:1,bypasses:0,hitRate:50,entries:1},json:{hits:0,misses:0,hitRate:null}},
      ecs:{wireAttempts:1,wireAccepted:1,wireRetries:0,jsonRetries:0},upstreams:[]},
      cnList:{domainCount:42,lastFetch:null},caches:{memory:{echCache:'warm'}}}});
  });
  await page.locator('#token').fill('testsecret');
  await page.locator('#refresh').click();
  await page.locator('#stats').waitFor();
  assert.match(await page.locator('#cache').textContent(),/50%/);
  assert.match(await page.locator('#jsonCache').textContent(),/—/);
  assert.match(await page.locator('#wire').textContent(),/SERVFAIL1/);
  await page.locator('#lock').click();
  assert.equal(await page.locator('#stats').isVisible(),false);
  assert.equal(await page.locator('#token').inputValue(),'');
  assert.equal(await page.locator('#wire').textContent(),'');
  assert.equal(errors.length,0,errors.join('\\n'));
  console.log('PASS authenticated monitor, no-sample state and lock');

} finally { await browser.close(); }
