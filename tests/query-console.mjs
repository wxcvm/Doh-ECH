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
  assert.equal(await page.locator('.preset').count(),6);
  assert.equal(await page.locator('#advanced').evaluate(e=>e.open),false);
  assert.equal(await page.locator('#dohUrl').textContent(),new URL('/doh',base).href);
  assert.equal(await page.locator('#echUrl').textContent(),new URL('/ech',base).href);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  console.log('PASS mobile layout and default addresses');

  await page.getByRole('button',{name:'普通 DNS',exact:false}).click();
  await page.locator('#cards .result-card').last().waitFor();
  await page.waitForFunction(()=>document.querySelector('#cards').children.length===3);
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
  for(const ip of ['invalid','114.114.114.114','223.5.5.5']){
    const response=await page.request.get(new URL('/api/query?domain=taobao.com&type=A&clientIp='+encodeURIComponent(ip),base).href);
    console.log('ECS DIAGNOSTIC '+ip+' '+await response.text());
  }
  for(const endpoint of ['https://dns.alidns.com/resolve','https://doh.pub/dns-query','https://cloudflare-dns.com/dns-query']){
    try{
      const response=await fetch(endpoint+'?name=taobao.com&type=1',{headers:{Accept:'application/dns-json'},signal:AbortSignal.timeout(5000)});
      console.log('UPSTREAM DIAGNOSTIC '+endpoint+' '+response.status+' '+(await response.text()).slice(0,1500));
    }catch(e){console.log('UPSTREAM DIAGNOSTIC '+endpoint+' '+e.message);}
  }
  for (const name of ['taobao.com','www.taobao.com','www.baidu.com','baidu.com']) {
    const response = await page.request.get(new URL('/api/query?domain='+name+'&type=A',base).href);
    console.log('DOMESTIC DIAGNOSTIC '+name+' '+response.status()+' '+(await response.text()).slice(0,1000));
  }
  await page.getByRole('button',{name:'国内解析',exact:false}).click();
  await page.locator('#cards [data-type=A] .status').waitFor();
  console.log('DOMESTIC PRESET '+await page.locator('#cards').textContent());
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
} finally { await browser.close(); }
