/**
 * DOH-ECH 
 * - 双上游竞速 + Edge 缓存
 * - CF/Meta 静态域名 + IPv6 + 仅 IPv4 排除
 * - 增强模式 + 自定义规则
 * - HTTPS hints 复用归属探测 IP
 *********自定义参数***************
 * - best 控制全局跟随优选，所有CF站点均使用配置的优选结果 默认false
 * - clientIp ECS支持，默认自动获取
 * - cf 解析优选域名的ip记录返回
 * - sub  CF优选订阅，格式 ip-https://ip.txt, cf-https://domain.txt
 * - exclude 过滤排除不合适的优选ip/domain
 * - shuffle  返回记录随机乱序开关 默认true
 * - area    返回订阅列表指定区域的ip记录 格式： hk,sg,电信,移动,us
 * - no6  全局屏蔽AAAA记录 默认false
 * - enhance (off/rule/full),rule：按rules参数规则返回,full:为所有非CF/Meta站点开启
 * *  - alpn ［h3］非CF/META站点-仅在enhance开启时生效 | CF/META站点-全局生效
 * *  - rules   仅在enhance开启时生效, 传参格式：*domain1,*domain2:ip1,ip2-noA-noAAAA,按rules参数规则为指定域名返回alpn仅h3 的HTTPS记录和优选可达的iphints 以及按规则决定是否屏蔽A/AAAA记录
 * *  - mandatory 指定浏览器必须理解的HTTPS参数，否则忽略整条记录
 */
// ===================== 全局配置 =====================
// ---------- 上游 DNS 配置（竞速取最快响应） ----------
// 国际上游 JSON 列表：用于境外域名的 A/AAAA/HTTPS 等结构化查询。
// 优化：仅保留稳定且快速的上游，移除不可靠的 Google
const UPSTREAM_JSON_LIST = [
    'https://dns.alidns.com/resolve',          // 阿里DNS（最快 ~200ms，国内首选）
    'https://doh.pub/dns-query',               // DNSPod（~300ms，腾讯）
    'https://cloudflare-dns.com/dns-query',    // Cloudflare 1.1.1.1（~500ms，国际）
];
// 国际上游二进制 DoH 列表：/doh 纯净转发端点使用，竞速取最快。
const UPSTREAM_DNS_LIST = [
    'https://dns.alidns.com/dns-query',        // 阿里DNS（最快）
    'https://doh.pub/dns-query',               // DNSPod
    'https://cloudflare-dns.com/dns-query',    // Cloudflare
];
// 国内上游 JSON 列表：仅用于国内域名分流（避免境外 DNS 对国内域名返回次优结果）。
const UPSTREAM_CN_JSON_LIST = [
    'https://dns.alidns.com/resolve',          // 阿里 DNS
    'https://doh.pub/dns-query',               // DNSPod（腾讯）
];
// Daily profile uses native DNS with separate domestic and international upstreams.
const BALANCED_CN_WIRE = UPSTREAM_DNS_LIST.slice(0, 2);
const BALANCED_INTL_WIRE = ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"];
const BALANCED_INTL_JSON = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
function balancedDomestic(domain) {
    if (!cnDomainSet) cnDomainSet = new Set(CN_DOMAIN_SUFFIXES);
    if (DIRECT_DOMAINS.some(d => domain === d || domain.endsWith("." + d))) return false;
    return isCNDomain(domain);
}
async function forwardBalanced(rawBuffer, domain) {
    const domestic = balancedDomestic(domain);
    const result = await forwardQuery(rawBuffer, domestic ? BALANCED_CN_WIRE : BALANCED_INTL_WIRE);
    const packet = await result.arrayBuffer();
    if (domestic && (new DataView(packet).getUint16(2) & 15) === 2) {
        const fallback = await forwardQuery(rawBuffer, BALANCED_INTL_WIRE);
        return dnsResponse(await fallback.arrayBuffer());
    }
    return dnsResponse(packet);
}
const DIRECT_JSON = ["https://cloudflare-dns.com/dns-query"];
const DIRECT_WIRE = ["https://cloudflare-dns.com/dns-query"];
const DIRECT_DOMAINS = ["google.com","google.com.hk","google.com.tw","google.co.jp","google.co.uk","google.de","google.fr","google.com.sg","googleapis.com","gstatic.com","googleusercontent.com","recaptcha.net","googlesource.com","gvt1.com","gvt2.com","x.com","twitter.com","t.co","twimg.com","twitterstatic.com"];
function isNativeDirect(domain, config) {
    return config.enhance === "direct" && DIRECT_DOMAINS.some(d => domain === d || domain.endsWith("."+d));
}
// Explicit per-client pins, never shared or inferred from another user's network.
function localDirectPins(domain, type, config) {
    if (!isNativeDirect(domain, config) || !config.pins || !['A','AAAA'].includes(type)) return [];
    const result = new Set();
    for (const entry of config.pins.split(';')) {
        const [host, list] = entry.split('=');
        if (host?.trim().toLowerCase().replace(/\.$/,'') !== domain || !list) continue;
        for (const value of list.split(',')) {
            const ip = value.trim();
            if (type === 'AAAA' && ip.includes(':') && ipv6ToBytes(ip)) result.add(formatIPv6(ipv6ToBytes(ip)));
            if (type === 'A' && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && ipToBytes(ip)) result.add(bytesToIp(ipToBytes(ip)));
        }
    }
    return [...result].slice(0, 8);
}
// Explicit X-only experimental profile, using the client's measured QUIC address.
function xHttp3Result(domain, type, config) {
    if (domain !== 'x.com' || !isNativeDirect(domain, config) || !config.xh3) return null;
    const ip = config.xh3.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !ipToBytes(ip)) return null;
    const address = bytesToIp(ipToBytes(ip));
    if (type === 'A') return { domain, type, answers: [address], rcode: 0, ttl: 30, policy: 'x-http3' };
    if (type === 'HTTPS') {
        // Chromium may ignore RRsets that exclusively disable the default ALPN.
        // Advertise H3 and H2; the client decides whether to race/fallback.
        const result = buildHttpsRecordFromParams(domain, [{key: 'alpn', val: 'h3,h2'}], [address], []);
        return { ...result, alpn: 'h3,h2', rcode: 0, ttl: 30, policy: 'x-http3' };
    }
    return null;
}
const SVC_PARAM_IDS = { mandatory: 0, alpn: 1, "no-default-alpn": 2, port: 3, ipv4hint: 4, ech: 5, ipv6hint: 6};// SVC PARAMS构造
const IPV4_ONLY_DOMAINS = ["twitter.com", "x.com", "t.co", "twimg.com"];// CDN IPv4-only policy; dl.google.com is handled by an opt-in rule below.
//Cloudflare 配置
const DEFAULT_CF_IP = "172.64.100.1,104.27.100.1,104.25.100.1,104.21.100.1,172.67.100.1,104.18.10.118";//默认CF优选IPv4(首选实测218ms;多IP返回,客户端自动容错切换)
const DEFAULT_CF_IP6 = "";//默认CF优选IPv6
// Only Cloudflare-operated domains are force-mapped by default. Other sites use real upstream DNS;
// opt-in best=true may still select a preferred address after an ownership check.
const CF_STATIC_DOMAINS = ["cloudflare-dns.com", "pages.dev", "workers.dev", "cloudflare.com"];
//Meta 配置
const DEFAULT_META_IP = "";//默认META优选IP
const META_DOMAINS = ["facebook.com", "messenger.com", "instagram.com","whatsapp.com", "fb.com", "meta.com"];//不查询-直接返回优选结果的META域名列表
const META_ECH_CONFIG = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=";//固定META ECH，过期自行更换

//enhance：rule/full下 ：增强规则列表,最高优先级，此列表内指定的ip直接作为A/AAAA IPhints返回，屏蔽记录规则优先级也高于全局屏蔽AAAA参数
const BUILTIN_HINTS = [
    {
        hosts:["https://raw.hellogithub.com/hosts.json"],
        noA:false, noAAAA: true
    },
    {
        // Upstream: Google regional search domains, same policy as GWS.
        domains: ["*.google.com.hk","*.google.com.tw","*.google.co.jp","*.google.co.kr","*.google.com.sg","*.google.co.id","*.google.co.in","*.google.com.my","*.google.co.th","*.google.com.vn","*.google.com.ph","*.google.com.pk","*.google.com.bd","*.google.com.kh","*.google.com.sa","*.google.ae","*.google.co.il","*.google.com.tr","*.google.kz","*.google.lt","*.google.co.uk","*.google.de","*.google.fr","*.google.it","*.google.es","*.google.pt","*.google.nl","*.google.be","*.google.ch","*.google.at","*.google.se","*.google.no","*.google.dk","*.google.fi","*.google.ie","*.google.pl","*.google.cz","*.google.gr","*.google.com.ua","*.google.ru","*.google.com","*.google.ca","*.google.com.mx","*.google.com.br","*.google.com.ar","*.google.cl","*.google.com.co","*.google.com.pe","*.google.com.ec","*.google.com.uy","*.google.co.ve","*.google.co.cr","*.google.com.au","*.google.co.nz","*.google.com.fj","*.google.co.za","*.google.com.eg","*.google.com.ng","*.google.co.ke","*.google.com.gh","*.google.co.ma","*.google.com.et"],
        ips: ["2001:4860:4826:7700::/64", "2001:4860:4827:7700::/64", "2001:4860:4828:7700::/64", "2001:4860:4829:7700::/64", "2001:4860:482a:7700::/64", "2001:4860:482b:7700::/64", "2001:4860:482c:7700::/64", "2001:4860:482d:7700::/64"],
        noA: true, noAAAA: false
    },
    {
        // FCM: preserve real dual-stack answers instead of Google IPv6-only defaults.
        domains: ["mobile-gtalk.l.google.com", "alt7-mtalk.google.com", "alt8-mtalk.google.com", "mtalk-dev.google.com", "mtalk-staging.google.com", "mtalk4.google.com", "alt1-mtalk.google.com", "alt2-mtalk.google.com", "alt3-mtalk.google.com", "alt4-mtalk.google.com", "alt5-mtalk.google.com", "alt6-mtalk.google.com", "mtalk.google.com"],
        ips: [], noA: false, noAAAA: false
    },
    {
        // Specific exceptions must override the broad Google/YouTube IPv6-only rules.
        // Apply only in opt-in enhancement modes, including ordinary non-CDN DNS paths.
        domains: ["*.music.youtube.com", "*.robinfrontend-pa.googleapis.com", "*.signaler-pa.googleapis.com", "*.dl.google.com"],
        ips: [], noA: false, noAAAA: true
    },
    {
        // GWS (Google Web Server) 分类组：承载网页主体、核心搜索 API、人机验证和账户安全登录 && GGC
        domains: [ "*.google.com.hk", "*.google.com","*.googleapis.com", "*.services.googleapis.cn", "*.services.google.com", "*.accounts.google.com","*.youtube.com", "*.youtube-nocookie.com", "*.googleapis.cn","*.recaptcha.net"],
        ips: ["2001:4860:4826:7700::/64", "2001:4860:4827:7700::/64", "2001:4860:4828:7700::/64", "2001:4860:4829:7700::/64", "2001:4860:482a:7700::/64", "2001:4860:482b:7700::/64", "2001:4860:482c:7700::/64", "2001:4860:482d:7700::/64"],
        noA: true,// 强制屏蔽 IPv4只留ipv6记录以绕过 GFW 的 v4 封锁
        noAAAA: false
    },
    {
        // GVS (Google Video Server) 分类组：专属于 YouTube 视频和音频大文件切片流媒体分发
        domains: ["*.googlevideo.com"],
        ips: [],
        noA: true,  noAAAA: false   
    },
    {
        // GGC (Google Global Cache) 分类组：专门分流并加速网页样式、Web 字体、浏览器更新及视频封面等静态资源
        domains: ["*.googlesource.com","*.gstatic.com", "*.googleusercontent.com", "*.ytimg.com", "*.ggpht.com", "*.gvt1.com","*.gvt2.com","*.googleadservices.com","*.googlesyndication.com","*.google-analytics.com","*.crashlytics.com","firebaseio.com","firebasedatabase.app"],
        ips: ["2001:4860:4826:7700::/64", "2001:4860:4827:7700::/64", "2001:4860:4828:7700::/64", "2001:4860:4829:7700::/64", "2001:4860:482a:7700::/64", "2001:4860:482b:7700::/64", "2001:4860:482c:7700::/64", "2001:4860:482d:7700::/64"],
        noA: true,    noAAAA: false      
    },
    {  
        // Meta 全家桶(禁用ipv4)（Instagram、Threads、Facebook 等）[此规则高于Meta优选ip]
        domains: ["*.meta.com","*.facebook.com", "*.fb.com","*.instagram.com", "*.cdninstagram.com", "*.fbcdn.net", "*.threads.net"],
        ips: [],
        noA: true, noAAAA: false
    },
    {
        // Wikipedia 维基百科(禁用ipv4)（全球最大的百科知识库，其通用任播边缘全面部署了支持 HTTP/3 的 ATS 架构）
        domains: ["*.wikipedia.org", "*.wikimedia.org", "*.wikibooks.org", "*.wikidata.org"],
        ips: [],  noA: true, noAAAA: false
    },
   //Others(禁用ipv4)
    { domains: ["*.docker.com", "*.docker.io", "*.production.cloudflare.docker.com"], ips: [], noA: true, noAAAA: false },       
    //FastlyCDN优化(禁用ipv6)
    { domains: ["*.reddit.com", "*.redd.it", "*.redditmedia.com", "*.redditstatic.com"], ips: ["151.101.1.140", "151.101.65.140", "151.101.129.140", "151.101.193.140"], noA: false, noAAAA: true },
    { domains: ["*.imgur.com", "*.i.imgur.com", "*.api.imgur.com", "*.s.imgur.com"], ips: ["151.101.1.193", "151.101.65.193", "151.101.129.193", "151.101.193.193"], noA: false, noAAAA: true },
    { domains: ["*.giphy.com", "*.media.giphy.com", "*.giphy.gif", "*.api.giphy.com"], ips: ["151.101.1.132", "151.101.65.132", "151.101.129.132", "151.101.193.132"], noA: false, noAAAA: true },
    { domains: ["*.pypi.org", "*.pythonhosted.org", "*.files.pythonhosted.org"], ips: ["151.101.1.223", "151.101.65.223", "151.101.129.223", "151.101.193.223"], noA: false, noAAAA: true },
    { domains: ["*.stackoverflow.com", "*.stackexchange.com", "*.sstatic.net"], ips: ["151.101.1.69", "151.101.65.69", "151.101.129.69", "151.101.193.69"], noA: false, noAAAA: true },
    { domains: ["*.duckduckgo.com", "*.ddg.gg", "*.icons.duckduckgo.com"], ips: ["151.101.1.181", "151.101.65.181", "151.101.129.181", "151.101.193.181"], noA: false, noAAAA: true },
    { domains: ["*.medium.com", "*.readmedium.com", "*.miro.medium.com"], ips: ["151.101.1.162", "151.101.65.162", "151.101.129.162", "151.101.193.162"], noA: false, noAAAA: true },
    { domains: ["*.pinterest.com", "*.pinimg.com", "*.pinterest.io", "*.media.pinterest.com"], ips: ["151.101.1.84", "151.101.65.84", "151.101.129.84", "151.101.193.84"], noA: false, noAAAA: true } 
    // 传统简单写法仍可混用（自动转换）
   //   ["*.googlevideo.com"] // 等价于 { domains: ["*.googlevideo.com"], ips: [], noA: false, noAAAA: false }
];

//CIDR归属列表
const RAW_META_CIDRS = ['31.13.24.0/21','31.13.64.0/18','45.64.40.0/22','57.141.0.0/24','57.141.2.0/23','57.141.4.0/22','57.141.8.0/21','57.141.16.0/23','57.144.0.0/14','66.220.144.0/20','69.63.176.0/20','69.171.224.0/19','74.119.76.0/22','102.132.96.0/20','102.132.112.0/24','102.132.114.0/23','102.132.116.0/23','102.132.119.0/24','102.132.120.0/23','102.132.123.0/24','102.132.125.0/24','102.132.126.0/23','102.221.188.0/22','103.4.96.0/22','129.134.0.0/17','129.134.130.0/24','129.134.135.0/24','129.134.136.0/22','129.134.140.0/24','129.134.143.0/24','129.134.144.0/24','129.134.147.0/24','129.134.148.0/23','129.134.154.0/23','129.134.156.0/22','129.134.160.0/22','129.134.164.0/23','129.134.168.0/21','129.134.176.0/20','129.134.194.0/24','157.240.0.0/17','157.240.128.0/23','157.240.131.0/24','157.240.132.0/24','157.240.134.0/24','157.240.136.0/23','157.240.139.0/24','157.240.156.0/23','157.240.159.0/24','157.240.169.0/24','157.240.175.0/24','157.240.177.0/24','157.240.179.0/24','157.240.181.0/24','157.240.182.0/23','157.240.184.0/21','157.240.192.0/18','163.70.128.0/17','163.77.132.0/23','163.77.136.0/23','163.114.128.0/20','173.252.64.0/18','179.60.192.0/22','185.60.216.0/22','185.89.216.0/22','199.201.64.0/22','204.15.20.0/22','2620:0:1c00::/40','2620:10d:c090::/44','2a03:2880::/32','2a03:2887:ff00::/48','2a03:2887:ff02::/48','2a03:2887:ff04::/46','2a03:2887:ff09::/48','2a03:2887:ff0a::/48','2a03:2887:ff1b::/48','2a03:2887:ff1c::/48','2a03:2887:ff1e::/48','2a03:2887:ff20::/48','2a03:2887:ff22::/47','2a03:2887:ff27::/48','2a03:2887:ff28::/46','2a03:2887:ff2f::/48','2a03:2887:ff30::/48','2a03:2887:ff33::/48','2a03:2887:ff37::/48','2a03:2887:ff38::/46','2a03:2887:ff3f::/48','2a03:2887:ff40::/46','2a03:2887:ff44::/47','2a03:2887:ff48::/46','2a03:2887:ff4d::/48','2a03:2887:ff4e::/47','2a03:2887:ff50::/45','2a03:2887:ff58::/47','2a03:2887:ff5a::/48','2a03:2887:ff5f::/48','2a03:2887:ff60::/48','2a03:2887:ff62::/47','2a03:2887:ff64::/46','2a03:2887:ff68::/47','2a03:2887:ff6a::/48','2a03:2887:ff70::/47','2c0f:ef78:3::/48','2c0f:ef78:5::/48','2c0f:ef78:9::/48','2c0f:ef78:c::/47','2c0f:ef78:e::/48','2c0f:ef78:10::/47'];
const RAW_CF_CIDRS = ['5.10.214.0/23','5.10.244.0/22','5.175.141.0/24','5.182.84.0/23','5.226.179.0/24','5.226.181.0/24','5.226.183.0/24','8.6.112.0/24','8.6.144.0/23','8.9.231.0/24','8.10.148.0/24','8.14.199.0/24','8.14.201.0/24','8.14.202.0/24','8.14.204.0/24','8.17.205.0/24','8.17.206.0/23','8.18.50.0/24','8.18.113.0/24','8.18.195.0/24','8.18.196.0/24','8.19.8.0/24','8.20.100.0/23','8.20.103.0/24','8.20.122.0/23','8.20.124.0/23','8.20.126.0/24','8.21.8.0/23','8.21.10.0/24','8.21.12.0/23','8.21.110.0/23','8.21.239.0/24','8.23.139.0/24','8.23.240.0/24','8.24.87.0/24','8.24.243.0/24','8.24.244.0/24','8.25.96.0/23','8.25.249.0/24','8.26.182.0/24','8.27.64.0/24','8.27.66.0/23','8.27.68.0/23','8.27.79.0/24','8.28.20.0/24','8.28.82.0/24','8.28.126.0/23','8.28.213.0/24','8.29.105.0/24','8.29.109.0/24','8.29.228.0/24','8.29.230.0/23','8.30.234.0/24','8.31.2.0/24','8.31.160.0/23','8.34.69.0/24','8.34.70.0/23','8.34.146.0/24','8.34.201.0/24','8.34.202.0/24','8.35.57.0/24','8.35.58.0/24','8.35.149.0/24','8.35.211.0/24','8.36.216.0/22','8.36.220.0/24','8.37.41.0/24','8.37.43.0/24','8.38.147.0/24','8.38.148.0/23','8.39.6.0/24','8.39.18.0/24','8.39.125.0/24','8.39.126.0/24','8.39.201.0/24','8.39.202.0/23','8.39.204.0/22','8.39.213.0/24','8.39.214.0/23','8.40.26.0/23','8.40.29.0/24','8.40.30.0/23','8.40.107.0/24','8.40.111.0/24','8.40.140.0/24','8.41.5.0/24','8.41.6.0/23','8.41.36.0/23','8.42.51.0/24','8.42.54.0/23','8.42.161.0/24','8.42.164.0/24','8.42.172.0/24','8.43.121.0/24','8.43.122.0/23','8.43.224.0/23','8.43.226.0/24','8.44.2.0/24','8.44.6.0/24','8.44.60.0/24','8.44.62.0/23','8.45.41.0/24','8.45.43.0/24','8.45.44.0/22','8.45.97.0/24','8.45.100.0/23','8.45.102.0/24','8.45.108.0/24','8.45.111.0/24','8.45.145.0/24','8.45.146.0/23','8.46.113.0/24','8.46.115.0/24','8.46.117.0/24','8.46.118.0/23','8.47.9.0/24','8.47.12.0/23','8.47.15.0/24','8.47.69.0/24','8.47.71.0/24','8.48.130.0/23','8.48.132.0/23','8.48.134.0/24','14.102.228.0/23','23.131.204.0/24','23.145.136.0/24','23.145.152.0/24','23.145.232.0/24','23.145.248.0/24','23.167.152.0/24','23.178.112.0/24','23.179.248.0/24','23.180.136.0/24','23.227.37.0/24','23.227.38.0/23','23.227.48.0/23','23.227.60.0/24','23.247.163.0/24','25.25.25.0/24','25.26.27.0/24','25.129.196.0/22','27.50.48.0/23','31.12.75.0/24','31.43.179.0/24','31.185.108.0/24','37.153.171.0/24','38.96.28.0/23','44.31.142.0/24','45.8.211.0/24','45.12.30.0/23','45.80.108.0/24','45.80.110.0/23','45.81.58.0/24','45.85.118.0/23','45.95.241.0/24','45.128.76.0/24','45.130.125.0/24','45.131.4.0/22','45.131.208.0/22','45.135.235.0/24','45.142.120.0/24','45.146.201.0/24','45.149.12.0/24','45.153.7.0/24','45.157.17.0/24','45.192.222.0/23','45.192.224.0/24','45.194.11.0/24','45.194.53.0/24','45.195.14.0/24','45.196.29.0/24','45.199.183.0/24','45.202.113.0/24','45.205.0.0/24','45.250.154.0/23','46.202.30.0/24','46.254.92.0/23','49.213.44.0/24','49.238.236.0/22','61.32.240.0/24','62.72.166.0/24','62.146.255.0/24','62.169.155.0/24','64.40.138.0/24','64.40.140.0/24','64.69.24.0/23','64.239.31.0/24','65.110.63.0/24','65.205.150.0/24','66.45.118.0/24','66.71.220.0/24','66.81.247.0/24','66.81.255.0/24','66.84.82.0/24','66.93.178.0/24','66.94.32.0/20','66.203.249.0/24','66.225.252.0/24','66.235.200.0/24','68.169.48.0/20','68.182.187.0/24','69.48.218.0/24','69.89.0.0/20','69.90.210.0/24','72.52.113.0/24','74.49.214.0/23','74.204.59.0/24','74.205.180.0/24','77.37.33.0/24','77.74.228.0/24','77.75.199.0/24','77.105.163.0/24','77.111.106.0/24','77.232.140.0/24','78.128.122.0/24','80.93.202.0/24','82.21.82.0/24','82.22.16.0/24','82.26.156.0/24','82.118.242.0/24','82.139.216.0/23','83.118.224.0/22','86.38.214.0/24','86.38.251.0/24','87.229.48.0/24','88.216.66.0/23','88.216.69.0/24','89.47.56.0/23','89.106.90.0/24','89.116.46.0/24','89.116.161.0/24','89.116.180.0/24','89.116.250.0/24','89.117.112.0/24','89.207.18.0/24','89.249.200.0/24','91.124.127.0/24','91.192.106.0/24','91.193.58.0/23','91.199.81.0/24','91.206.71.0/24','91.209.253.0/24','92.53.188.0/22','92.60.74.0/24','92.243.74.0/23','93.114.64.0/23','93.115.102.0/24','94.140.0.0/24','94.156.10.0/24','94.247.142.0/24','96.43.100.0/23','102.132.188.0/24','102.177.176.0/24','102.177.189.0/24','103.11.212.0/24','103.11.214.0/24','103.15.85.0/24','103.19.144.0/23','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','103.31.79.0/24','103.81.228.0/24','103.112.176.0/24','103.116.7.0/24','103.121.59.0/24','103.133.1.0/24','103.135.208.0/23','103.169.142.0/24','103.172.110.0/23','103.186.74.0/24','103.198.92.0/24','103.204.13.0/24','103.215.22.0/24','103.219.64.0/22','103.245.228.0/23','104.16.0.0/13','104.24.0.0/14','104.28.0.0/16','104.29.0.0/21','104.29.8.0/23','104.29.11.0/24','104.29.12.0/22','104.29.16.0/23','104.29.19.0/24','104.29.20.0/22','104.29.24.0/21','104.29.32.0/24','104.29.34.0/23','104.29.36.0/22','104.29.40.0/22','104.29.44.0/23','104.29.47.0/24','104.29.48.0/23','104.29.50.0/24','104.29.52.0/22','104.29.57.0/24','104.29.59.0/24','104.29.61.0/24','104.29.62.0/23','104.29.64.0/23','104.29.67.0/24','104.29.68.0/22','104.29.72.0/21','104.29.80.0/23','104.29.82.0/24','104.29.85.0/24','104.29.86.0/24','104.29.88.0/21','104.29.96.0/22','104.29.100.0/23','104.29.102.0/24','104.29.104.0/21','104.29.112.0/22','104.29.116.0/23','104.29.121.0/24','104.29.122.0/23','104.29.124.0/22','104.29.128.0/18','104.30.0.0/19','104.30.32.0/23','104.30.128.0/23','104.30.132.0/22','104.30.136.0/23','104.30.144.0/21','104.30.160.0/19','104.31.0.0/21','104.31.16.0/22','104.31.20.0/24','104.36.195.0/24','104.129.164.0/22','104.156.176.0/23','104.165.248.0/24','104.234.239.0/24','104.239.72.0/24','104.254.140.0/24','108.162.192.0/18','108.165.152.0/24','108.165.216.0/24','109.234.211.0/24','114.129.43.0/24','123.108.75.0/24','130.108.73.0/24','130.108.104.0/23','130.108.121.0/24','130.108.253.0/24','131.0.72.0/22','131.167.255.0/24','136.143.138.0/24','137.66.96.0/24','138.5.248.0/24','138.226.234.0/24','138.249.21.0/24','139.64.234.0/23','140.99.233.0/24','141.11.202.0/23','141.101.64.0/18','141.193.213.0/24','143.14.224.0/24','143.14.229.0/24','143.14.251.0/24','143.20.247.0/24','144.124.211.0/24','147.78.140.0/24','147.185.161.0/24','148.227.167.0/24','150.48.128.0/18','151.243.128.0/22','151.243.133.0/24','151.246.216.0/23','152.114.0.0/17','152.114.128.0/18','154.51.129.0/24','154.51.160.0/24','154.62.129.0/24','154.81.141.0/24','154.83.2.0/24','154.83.22.0/23','154.83.30.0/24','154.84.14.0/23','154.84.16.0/24','154.84.18.0/24','154.84.20.0/23','154.84.24.0/24','154.84.26.0/23','154.90.70.0/24','154.92.9.0/24','154.193.133.0/24','154.193.184.0/24','154.194.12.0/24','154.194.225.0/24','154.197.64.0/23','154.197.75.0/24','154.197.80.0/24','154.197.88.0/24','154.197.108.0/24','154.197.121.0/24','154.198.173.0/24','154.200.89.0/24','154.202.89.0/24','154.206.12.0/24','154.207.77.0/24','154.207.79.0/24','154.207.127.0/24','154.207.189.0/24','154.207.252.0/23','154.211.8.0/24','154.218.15.0/24','154.219.5.0/24','154.223.134.0/23','155.46.167.0/24','155.46.213.0/24','156.224.73.0/24','156.225.72.0/24','156.243.83.0/24','156.243.246.0/24','156.246.69.0/24','156.246.70.0/24','156.252.2.0/23','156.255.123.0/24','158.94.212.0/24','159.112.235.0/24','159.242.242.0/24','159.246.55.0/24','160.153.0.0/24','161.248.134.0/23','162.44.32.0/22','162.44.118.0/23','162.44.208.0/23','162.120.94.0/24','162.158.0.0/15','162.251.82.0/24','162.251.205.0/24','164.38.155.0/24','164.77.28.0/23','165.101.60.0/23','167.1.137.0/24','167.1.148.0/23','167.1.150.0/24','167.1.181.0/24','167.68.4.0/23','167.68.11.0/24','167.68.42.0/24','167.74.94.0/23','167.74.130.0/24','169.40.133.0/24','169.197.101.0/24','170.114.45.0/24','170.114.46.0/24','170.114.52.0/24','170.114.78.0/24','170.168.7.0/24','170.176.152.0/24','170.176.163.0/24','172.64.0.0/13','172.83.72.0/23','172.83.76.0/24','173.0.92.0/24','173.245.48.0/20','176.103.113.0/24','176.124.223.0/24','176.126.206.0/23','178.94.249.0/24','178.211.142.0/24','178.213.76.0/24','181.214.1.0/24','182.23.210.0/24','184.174.80.0/24','185.7.190.0/23','185.7.240.0/24','185.18.184.0/24','185.18.250.0/24','185.29.76.0/24','185.38.25.0/24','185.38.135.0/24','185.60.251.0/24','185.122.0.0/24','185.126.66.0/24','185.132.85.0/24','185.132.86.0/23','185.133.172.0/24','185.135.9.0/24','185.146.172.0/23','185.148.104.0/22','185.149.135.0/24','185.156.19.0/24','185.158.133.0/24','185.159.247.0/24','185.162.228.0/22','185.170.166.0/24','185.176.24.0/24','185.176.26.0/24','185.178.196.0/22','185.193.28.0/22','185.207.92.0/24','185.207.196.0/22','185.209.154.0/24','185.229.206.0/24','185.238.228.0/24','185.251.80.0/23','188.42.88.0/23','188.42.98.0/24','188.42.145.0/24','188.95.12.0/24','188.114.96.0/20','188.164.158.0/23','188.164.248.0/24','188.244.122.0/24','190.93.240.0/20','192.65.217.0/24','192.71.82.0/24','192.86.150.0/24','192.103.56.0/24','192.133.11.0/24','192.152.138.0/24','192.236.26.0/24','193.8.237.0/24','193.9.49.0/24','193.16.63.0/24','193.17.206.0/24','193.67.144.0/24','193.124.18.0/24','193.124.224.0/24','193.162.35.0/24','193.202.90.0/24','193.227.99.0/24','193.233.21.0/24','193.233.132.0/24','194.1.194.0/24','194.26.68.0/24','194.36.49.0/24','194.36.55.0/24','194.39.112.0/21','194.41.114.0/24','194.53.53.0/24','194.59.5.0/24','194.113.223.0/24','194.152.44.0/24','194.169.194.0/24','195.26.229.0/24','195.28.190.0/23','195.82.109.0/24','195.85.23.0/24','195.85.59.0/24','195.189.177.0/24','195.242.122.0/23','195.245.221.0/24','195.250.46.0/24','196.13.241.0/24','196.207.45.0/24','197.234.240.0/22','198.41.128.0/17','198.177.56.0/23','198.202.211.0/24','198.217.251.0/24','198.252.206.0/24','199.5.242.0/24','199.27.128.0/21','199.33.230.0/23','199.33.232.0/23','199.60.103.0/24','199.181.197.0/24','200.73.67.0/24','202.27.69.0/24','202.82.250.0/24','203.6.66.0/24','203.6.74.0/24','203.13.32.0/24','203.17.126.0/24','203.19.222.0/24','203.22.223.0/24','203.22.241.0/24','203.23.103.0/24','203.23.104.0/24','203.23.106.0/24','203.24.102.0/23','203.24.108.0/23','203.28.8.0/23','203.29.52.0/22','203.30.188.0/22','203.32.120.0/23','203.34.28.0/24','203.34.80.0/24','203.55.107.0/24','203.89.5.0/24','203.168.128.0/22','203.168.192.0/20','204.62.141.0/24','204.68.111.0/24','204.69.207.0/24','204.153.16.0/24','204.195.192.0/18','205.233.181.0/24','207.189.149.0/24','208.42.188.0/24','208.77.33.0/24','208.77.35.0/24','208.88.71.0/24','208.100.60.0/24','209.46.30.0/24','209.55.226.0/24','209.55.232.0/24','209.55.234.0/24','209.55.246.0/23','209.55.253.0/24','209.55.254.0/24','209.222.114.0/23','212.6.39.0/24','212.22.76.0/24','212.104.128.0/24','212.239.86.0/24','213.182.199.0/24','213.219.247.0/24','213.241.198.0/24','216.19.107.0/24','216.74.106.0/24','216.120.131.0/24','216.120.180.0/23','216.154.208.0/20','216.163.179.0/24','216.198.53.0/24','216.198.54.0/24','216.205.52.0/24','216.224.121.0/24','223.27.176.0/23','2001:503:ff40::/46','2001:678:19c::/48','2001:df7:6e80::/48','2400:c760:a::/48','2400:cb00::/32','2405:8100::/32','2405:b500::/32','2407:30c0:180::/46','2602:80c:cf::/48','2602:f660::/40','2602:f830::/48','2606:2c0:20::/47','2606:2c40::/48','2606:4700::/32','2606:54c0::/32','2606:54c1::/48','2606:54c1:2::/47','2606:54c1:6::/47','2606:54c1:8::/46','2606:54c1:c::/47','2606:54c1:10::/46','2606:54c2::/47','2606:54c2:2::/48','2606:54c3::/45','2606:ae80:10::/48','2607:8940:2000::/35','2607:9240:201::/48','2607:9240:202::/47','2620:78:200f::/48','2620:cb:2000::/48','2620:117:bfb0::/44','2620:127:f00c::/46','2620:12c:90af::/48','2620:132:1000::/48','2803:f800::/32','2a02:d21:20::/44','2a03:f940::/48','2a05:7880::/32','2a06:98c0::/29','2a06:9ac0::/32','2a07:180::/32','2a08:600::/48','2a08:600:e0::/47','2a08:600:ee::/47','2a08:600:ff::/48','2a09:bac0:4::/48','2a09:bac0:11::/48','2a09:bac0:12::/48','2a09:bac0:14::/46','2a09:bac0:19::/48','2a09:bac0:20::/46','2a09:bac0:26::/47','2a09:bac0:28::/47','2a09:bac0:31::/48','2a09:bac0:34::/47','2a09:bac0:38::/47','2a09:bac0:40::/48','2a09:bac0:43::/48','2a09:bac0:44::/47','2a09:bac0:47::/48','2a09:bac0:48::/47','2a09:bac0:50::/48','2a09:bac0:52::/48','2a09:bac0:54::/48','2a09:bac0:57::/48','2a09:bac0:59::/48','2a09:bac0:63::/48','2a09:bac0:64::/46','2a09:bac0:68::/47','2a09:bac0:70::/46','2a09:bac0:74::/47','2a09:bac0:78::/47','2a09:bac0:80::/47','2a09:bac0:83::/48','2a09:bac0:84::/47','2a09:bac0:87::/48','2a09:bac0:88::/47','2a09:bac0:94::/48','2a09:bac0:96::/47','2a09:bac0:98::/48','2a09:bac0:100::/48','2a09:bac0:102::/47','2a09:bac0:106::/47','2a09:bac0:109::/48','2a09:bac0:113::/48','2a09:bac0:114::/47','2a09:bac0:116::/48','2a09:bac0:119::/48','2a09:bac0:120::/47','2a09:bac0:123::/48','2a09:bac0:124::/47','2a09:bac0:128::/48','2a09:bac0:130::/48','2a09:bac0:132::/48','2a09:bac0:134::/48','2a09:bac0:136::/47','2a09:bac0:138::/48','2a09:bac0:143::/48','2a09:bac0:145::/48','2a09:bac0:149::/48','2a09:bac0:151::/48','2a09:bac0:152::/47','2a09:bac0:154::/47','2a09:bac0:156::/48','2a09:bac0:158::/47','2a09:bac0:160::/48','2a09:bac0:162::/48','2a09:bac0:165::/48','2a09:bac0:166::/47','2a09:bac0:168::/47','2a09:bac0:172::/48','2a09:bac0:174::/48','2a09:bac0:181::/48','2a09:bac0:185::/48','2a09:bac0:192::/47','2a09:bac0:194::/48','2a09:bac0:196::/47','2a09:bac0:199::/48','2a09:bac0:202::/47','2a09:bac0:212::/48','2a09:bac0:216::/47','2a09:bac0:218::/48','2a09:bac0:227::/48','2a09:bac0:228::/48','2a09:bac0:237::/48','2a09:bac0:243::/48','2a09:bac0:246::/48','2a09:bac0:254::/48','2a09:bac0:268::/47','2a09:bac0:270::/48','2a09:bac0:275::/48','2a09:bac0:281::/48','2a09:bac0:282::/47','2a09:bac0:284::/47','2a09:bac0:298::/47','2a09:bac0:301::/48','2a09:bac0:337::/48','2a09:bac0:338::/47','2a09:bac0:341::/48','2a09:bac0:343::/48','2a09:bac0:346::/48','2a09:bac0:352::/48','2a09:bac0:358::/48','2a09:bac0:360::/48','2a09:bac0:374::/48','2a09:bac0:376::/48','2a09:bac0:380::/47','2a09:bac0:382::/48','2a09:bac0:384::/47','2a09:bac0:388::/48','2a09:bac0:390::/47','2a09:bac0:393::/48','2a09:bac0:403::/48','2a09:bac0:404::/48','2a09:bac0:407::/48','2a09:bac0:408::/48','2a09:bac0:411::/48','2a09:bac0:412::/48','2a09:bac0:423::/48','2a09:bac0:428::/48','2a09:bac0:431::/48','2a09:bac0:439::/48','2a09:bac0:441::/48','2a09:bac0:445::/48','2a09:bac0:448::/48','2a09:bac0:450::/48','2a09:bac0:453::/48','2a09:bac0:455::/48','2a09:bac0:458::/48','2a09:bac0:462::/48','2a09:bac0:464::/48','2a09:bac0:466::/47','2a09:bac0:470::/48','2a09:bac0:472::/48','2a09:bac0:476::/47','2a09:bac0:478::/48','2a09:bac0:481::/48','2a09:bac0:483::/48','2a09:bac0:485::/48','2a09:bac0:497::/48','2a09:bac0:507::/48','2a09:bac0:522::/47','2a09:bac0:525::/48','2a09:bac0:532::/47','2a09:bac0:534::/48','2a09:bac0:537::/48','2a09:bac0:538::/48','2a09:bac0:542::/47','2a09:bac0:557::/48','2a09:bac0:558::/47','2a09:bac0:566::/47','2a09:bac0:572::/47','2a09:bac0:574::/48','2a09:bac0:581::/48','2a09:bac0:582::/47','2a09:bac0:594::/48','2a09:bac0:597::/48','2a09:bac0:598::/48','2a09:bac0:601::/48','2a09:bac0:612::/48','2a09:bac0:618::/47','2a09:bac0:626::/48','2a09:bac0:631::/48','2a09:bac0:632::/47','2a09:bac0:636::/47','2a09:bac0:641::/48','2a09:bac0:646::/48','2a09:bac0:649::/48','2a09:bac0:650::/48','2a09:bac0:658::/48','2a09:bac0:663::/48','2a09:bac0:670::/48','2a09:bac0:677::/48','2a09:bac0:679::/48','2a09:bac0:684::/48','2a09:bac0:694::/48','2a09:bac0:704::/48','2a09:bac0:711::/48','2a09:bac0:712::/48','2a09:bac0:719::/48','2a09:bac0:721::/48','2a09:bac0:724::/47','2a09:bac0:735::/48','2a09:bac0:745::/48','2a09:bac0:748::/48','2a09:bac0:920::/48','2a09:bac0:1000::/47','2a09:bac0:1008::/45','2a09:bac1::/32','2a09:bac2::/31','2a09:bac4::/30','2a0a:6c80::/29','2a0b:4144::/48','2a0b:85c7:ffff::/48','2a13:9500:3e::/48','2a14:7ac0::/48','2a14:a087::/47','2c0f:f248::/32'];
// 第三方维护的国内域名列表
const CN_DOMAIN_LIST_URL = 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt';
// 国内域名后备后缀（远程列表加载失败时使用）
const CN_DOMAIN_SUFFIXES = ['jd.com','meituan.com','taobao.com', '.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn'];

// ===================== 缓存逻辑 =====================
let cnDomainSet = null;
let cnDomainLastFetch = 0;
let cnRefreshRunning = false;
let cnRetryAt = 0;
globalThis.__workerStartTime = globalThis.__workerStartTime || Date.now();
const CN_DOMAIN_CACHE_TTL = 7 * 24 * 3600 * 1000;   // 每7天更新CN列表
const cacheMap = new Map();
function rememberCacheEntry(key, entry) {
    if (cacheMap.size > 20000) {
        for (const k of cacheMap.keys()) {
            cacheMap.delete(k);
            if (cacheMap.size <= 15000) break;
        }
    }
    cacheMap.set(key, entry);
}
const ECH_CACHE_TTL = 3600 * 1000;              //ech缓存1小时
const SUB_CACHE_TTL =  24 * 3600 * 1000;      //订阅缓存1天
const subCache = new Map();
const RANDOM_IPV6_COUNT = 2;                  // 每个前缀生成 2 个随机 IP
const PREFIX_CACHE_TTL = 24 * 3600 * 1000;       // 前缀缓存24小时
const prefixCache = new Map();
const MAX_PRESCREEN = 10;//候选记录最多条目
const MAX_FINAL = 6;//记录最终返回最多条目
const HOSTS_CACHE_TTL =24 * 3600 * 1000;   // hosts 缓存24小时
const hostsCache = new Map();
// 延迟编译 CIDR 
let compiledMeta = null, compiledCF = null;
function getCompiledMeta() { if (!compiledMeta) compiledMeta = compileCidrs(RAW_META_CIDRS); return compiledMeta; }
function getCompiledCF()   { if (!compiledCF)   compiledCF   = compileCidrs(RAW_CF_CIDRS);   return compiledCF; }

// ===================== 参数构建 =====================
function buildConfig(url, headers = null) {
    const get = (p, h) => (url.searchParams.get(p) || (headers ? headers.get(h) : null)) || '';
   
 const config =  {
        ip4: get('ip4', 'X-Ip4'), ip6: get('ip6', 'X-Ip6'),
        metaIp4: get('metaIp4', 'X-MetaIp4'), metaIp6: get('metaIp6', 'X-MetaIp6'),
        cfDomain: get('cf', 'X-CF'), metaDomain: get('meta', 'X-Meta'),
        echDomain: get('ech', 'X-ECH') || 'cloudflare-ech.com',
        best: get('best', 'X-Best') || 'false', sub: get('sub', 'X-Sub'),
        exclude: get('exclude', 'X-Exclude'), shuffle: get('shuffle', 'X-Shuffle') || 'true',
        area: get('area', 'X-Area'), enhance: get('enhance', 'X-Enhance') || 'off',
        pins: get('pins', 'X-Pins'), xh3: get('xh3', 'X-XH3'), rules: get('rules', 'X-Rules'), alpn: get('alpn', 'X-Alpn') || 'h3,h2',
        clientIp: get('clientIp', 'X-ClientIP') || '',
        no6: get('no6', 'X-No6') || 'false',   
        mandatory: get('mandatory', 'X-Mandatory') || 'alpn',
        nocf6: get('nocf6', 'X-NoCF6') || 'true'
    };
    config.ip4 = prescreenIpList(config.ip4);//预筛选
    config.ip6 = prescreenIpList(config.ip6);
    return config;
}
// ===================== Worker 入口 =====================
// Once-per-isolate warmup: avoid starting three independent tasks for every DNS query.
let nextWarmupAt = 0;
function scheduleRuntimeWarmup(ctx) {
    const now = Date.now();
    if (now < nextWarmupAt) return;
    nextWarmupAt = now + 60_000;
    ctx.waitUntil(Promise.allSettled([
        ensureCNDomainSet(),
        fetchRealEch('cloudflare-ech.com', ''),
        getBuiltinRulesMap()
    ]));
}
export default {
    async fetch(req, env, ctx) {
        scheduleRuntimeWarmup(ctx);
        const url = new URL(req.url);
        // 浏览器端 JS 客户端跨域 POST application/dns-message 会先发 OPTIONS 预检
        if (req.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Ip4, X-Ip6, X-MetaIp4, X-MetaIp6, X-CF, X-Meta, X-ECH, X-Best, X-Sub, X-Exclude, X-Shuffle, X-Pins, X-XH3, X-Area, X-Enhance, X-Rules, X-Alpn, X-ClientIP, X-No6, X-Mandatory, X-NoCF6',
                    'Access-Control-Max-Age': '86400'
                }
            });
        }
        if (url.pathname === '/log') {
            // Debug information is private: fail closed if no admin token is configured.
            if (!env?.DOH_ADMIN_TOKEN || req.headers.get('Authorization') !== 'Bearer ' + env.DOH_ADMIN_TOKEN) {
                return new Response('Not Found', { status: 404 });
            }
            return handleLogsRequest();
        }
        if (url.pathname === '/sub.txt') {
            // CF 优选 IP 订阅（配合 sub=ip-https://... 参数使用）
            const subContent = [
                '172.64.100.1', '104.27.100.1', '104.25.100.1', '104.21.100.1',
                '104.19.100.1', '172.65.100.1', '172.67.100.1', '104.18.11.118',
                '104.16.0.1', '104.18.10.118',
            ].join('\n') + '\n';
            return new Response(subContent, {
                headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600, s-maxage=3600' }
            });
        }
        const clientIP = url.searchParams.get('clientIp') || req.headers.get('X-ClientIP') || req.headers.get('CF-Connecting-IP') || '';
        if (url.pathname === '/api/query') return handleApiQuery(url, clientIP, env);
        if (url.pathname === '/ech' || url.pathname === '/dns-query') return handleDoHRequest(req, true, ctx, clientIP, env);
        if (url.pathname === '/doh') return handleDoHRequest(req, false, ctx, clientIP, env);
        if (url.pathname === '/' || url.pathname === '/index.html') {
            return new Response(getHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600, s-maxage=3600' } });
        }
        // 兼容：客户端把 DoH 地址误配成站点根或任意路径（Chrome/dnsproxy 常见）。
        // 只要具备标准 DoH 请求特征就按 /ech 语义处理，避免误配后收到 404 或 HTML。
        const ct = (req.headers.get('Content-Type') || '').toLowerCase();
        if ((req.method === 'POST' && ct.includes('application/dns-message')) ||
            (req.method === 'GET' && url.searchParams.get('dns'))) {
            return handleDoHRequest(req, true, ctx, clientIP, env);
        }
        return new Response(JSON.stringify({
            error: 'Not Found',
            path: url.pathname,
            endpoints: ['/', '/ech', '/doh', '/dns-query', '/api/query', '/sub.txt', '/log']
        }, null, 2), {
            status: 404,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
        });
    },
    // Cron 定时预热：保持缓存热状态（国内域名库/ECH/规则），避免冷启动首请求降速
    async scheduled(controller, env, ctx) {
        ctx.waitUntil(ensureCNDomainSet());
        ctx.waitUntil(fetchRealEch('cloudflare-ech.com', ''));
        ctx.waitUntil(getBuiltinRulesMap());
        // Warm this deployment's resolver caches, never a hardcoded third-party host.
        ctx.waitUntil(Promise.allSettled([
            queryUpstreamDNS('example.com', 1),
            queryUpstreamDNS('cloudflare-ech.com', 65),
            queryUpstreamDNS('taobao.com', 1)
        ]));
    }
};

// ===================== DoH 处理 =====================
// Limit the actual streaming bytes; Content-Length alone is not reliable.
async function readLimitedDnsBody(req, maxBytes) {
    if (Number(req.headers.get('Content-Length') || 0) > maxBytes) return null;
    if (!req.body) return new ArrayBuffer(0);
    const reader = req.body.getReader();
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel();
                return null;
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result.buffer;
}


// DoH GET 请求缓存（仅缓存静态域名 + 固定参数）
const DOH_GET_CACHE = new Map();
const DOH_GET_TTL = 300000; // 5分钟

async function handleDoHRequest(req, injectEch, ctx, clientIP, env) {
    const url = new URL(req.url);
    const config = buildConfig(url, req.headers);
    if (!config.clientIp) config.clientIp = clientIP;
    // Pure forwarding must not fetch user-provided subscription URLs.
    if (injectEch && config.enhance !== 'balanced') await applySubConfig(config, env);

    if (req.method === 'POST') {
        const contentType = (req.headers.get('Content-Type') || '').toLowerCase();
        if (!/^application\/dns-message(?:\s*;|\s*$)/.test(contentType)) {
            return json({ error: 'POST requires application/dns-message' }, 415);
        }
        const buf = await readLimitedDnsBody(req, 65535);
        if (!buf) return json({ error: 'DNS request too large' }, 413);
        if (buf.byteLength < 12) return json({ error: 'Malformed DNS wire message' }, 400);
        if (injectEch) return handleDnsQuery(buf, config, ctx, config.clientIp);
        const res = await forwardQuery(buf);
        return dnsResponse(await res.arrayBuffer());
    }
    if (req.method === 'GET' && url.searchParams.get('dns')) {
        const dnsParam = url.searchParams.get('dns');
        if (!/^[A-Za-z0-9_-]+={0,2}$/.test(dnsParam) || dnsParam.length > 8192) {
            return json({ error: 'Invalid base64url DNS query' }, 400);
        }
        const raw = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
        // 非法字符 / 超长参数必须在解码前拦住：否则 atob 抛错会变成 Cloudflare 500 文本页
        // （无 CORS 头，也不是 RFC8484 错误响应），配置错误的客户端还会照常重试。
        let buf;
        try {
            if (raw.length > 8192) throw new Error('too long');
            buf = Uint8Array.from(atob(raw), c => c.charCodeAt(0)).buffer;
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid ?dns= parameter', hint: 'RFC8484 base64url 编码的 DNS 报文，长度上限 8192' }, null, 2), {
                status: 400,
                headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        if (buf.byteLength < 12) return json({ error: 'Malformed DNS wire message' }, 400);

        // GET and POST share the same parsing, forwarding and synthesis path.
        if (injectEch) return handleDnsQuery(buf, config, ctx, config.clientIp);
        const res = await forwardQuery(buf);
        return dnsResponse(await res.arrayBuffer());
    }
    // 既非 POST 线格式、也无 ?dns= 参数：这不是一个合法的 RFC8484 DoH 请求。
    // 早期版本返回 200 "OK"，会让配置错误的客户端把空响应当作有效结果并缓存，必须显式报错。
    return new Response(JSON.stringify({
        error: 'Invalid DoH request',
        hint: '本端点是 RFC8484 DoH：请使用 POST + Content-Type: application/dns-message，或 GET ?dns=<base64url>',
        node: '若需要 JSON 查询请使用 /api/query?domain=example.com&type=A'
    }, null, 2), {
        status: 400,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
}

// ===================== DNS 查询入口 =====================
// ns：缓存命名空间。'ech' = 注入构造端点，'doh' = 纯净转发端点；两者结果语义不同，绝不共用缓存键。
async function handleDnsQuery(rawBuffer, config, ctx, clientIP) {
    try {
        const query = parseDnsPacket(rawBuffer);
        if (!query?.questions?.length) return forwardQuery(rawBuffer);
        const { id, questions } = query;
        const echoEdns = !!query.hasEdns;
        const qType = questions[0].type;
        const qName = questions[0].name.toLowerCase().replace(/\.$/, "");
        // 原样保留客户端发来的大小写：使用 DNS-0x20 随机化的客户端/解析器会校验
        // 响应 question 与请求逐字节一致，统一转小写会导致其丢弃响应。
        const rawQName = questions[0].name.replace(/\.$/, "");
        // Balanced mode preserves complete upstream wire responses, including CNAME, HTTPS and DNSSEC.
        if (config.enhance === 'balanced' && questions.length === 1 && questions[0].qclass === 1 &&
            (new DataView(rawBuffer).getUint16(2) & 0x7800) === 0) return forwardBalanced(rawBuffer, qName);
        // Non-IN, multi-question, non-QUERY, or DNSSEC-sensitive packets must be forwarded untouched.
        const header = new DataView(rawBuffer);
        if (header.getUint16(4) !== 1 || (header.getUint16(2) & 0x7800) !== 0 ||
            questions[0].qclass !== 1 || query.dnssecOk || query.questionCompressed) {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }
        // 但缓存体是跨客户端共享的，无法同时承载多种大小写；因此只缓存全小写(常规)查询。
        const caseNeutral = rawQName === rawQName.toLowerCase();

        // Direct profile is explicit, scoped and preserves native DNS packets (including HTTPS/SVCB).
        if (isNativeDirect(qName, config)) {
            const type = qType === 1 ? 'A' : qType === 28 ? 'AAAA' : qType === 65 ? 'HTTPS' : '';
            const h3 = xHttp3Result(qName, type, config);
            if (h3) return dnsResponseFromResult(id, rawQName, qType, h3, echoEdns);
            const pins = localDirectPins(qName, type, config);
            if (pins.length) return dnsResponseFromResult(id, rawQName, qType, { answers: pins, ttl: 30 }, echoEdns);
            const res = await forwardQuery(rawBuffer, DIRECT_WIRE);
            const packet = await res.arrayBuffer();
            if ((new DataView(packet).getUint16(2) & 15) !== 2) return dnsResponse(packet);
            const fallback = await forwardQuery(rawBuffer);
            return dnsResponse(await fallback.arrayBuffer());
        }

        // 假名处理
        if (qName === "cf.ech" || qName === "fb.ech") {
            if (qType === 65) {
                const result = await buildFakeEchResponse(config, qName, clientIP, qName === "cf.ech");
                return dnsResponseFromResult(id, rawQName, 65, result, echoEdns);
            }
            return dnsResponse(createMultiAnsResponse(id, qName, qType, [], 3600, echoEdns));
        }

        // 本端点只会合成 A(1)/AAAA(28)/HTTPS(65) 三类记录。
        // 其余类型（TXT/MX/NS/SRV/CAA/SOA/PTR…）必须原样转发：否则会被当作 A 解析，
        // 再按请求方的 qType 打包，产出「类型是 TXT、内容是 4 字节 IPv4」的畸形记录。
        if (qType !== 1 && qType !== 28 && qType !== 65) {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }

        const isStaticCF = CF_STATIC_DOMAINS.some(d => qName === d || qName.endsWith("." + d));
        const isStaticMeta = META_DOMAINS.some(d => qName === d || qName.endsWith("." + d));

        if (isStaticCF || isStaticMeta) {
            // 静态域名：读缓存（Map + Cache API 二级），miss 则计算并写回。
            // 关键：缓存键不含任何参数维度，因此只有"结果与参数无关"的请求才允许读写缓存，
            // 否则带 ip4/ip6/no6/enhance/rules/alpn 的请求会污染全站缓存（或反过来被默认结果屏蔽）。
            // 缓存体固定为 ID=0、不含 OPT 的规范形式：读取时再回写事务 ID、按需追加 OPT。
            const cacheable = caseNeutral && isCacheableStaticRequest(qName, config, qType === 28 ? 'AAAA' : qType === 1 ? 'A' : 'HTTPS');
            const cKey = cacheable ? `ech-v2:${qName}:${qType}` : null;
            if (cKey) {
                const cachedIt = DOH_GET_CACHE.get(cKey);
                if (cachedIt && Date.now() < cachedIt.expire) {
                    const body = withDnsId(cachedIt.body, id);
                    return dnsResponse(echoEdns ? appendOpt(body) : body, { 'X-Cache': 'DOH_HIT' });
                }
                try {
                    const sharedRes = await caches.default.match(`https://dns-cache/ech-v2/${qName}:${qType}`);
                    if (sharedRes) {
                        const sBody = await sharedRes.arrayBuffer();
                        DOH_GET_CACHE.set(cKey, { body: sBody, expire: Date.now() + DOH_GET_TTL });
                        const body = withDnsId(sBody, id);
                        return dnsResponse(echoEdns ? appendOpt(body) : body, { 'X-Cache': 'DOH_HIT' });
                    }
                } catch (e) {}
            }
            const result = await resolveDNS(qName, qType === 28 ? 'AAAA' : (qType === 65 ? 'HTTPS' : 'A'), config, clientIP);
            if (!cKey) return dnsResponseFromResult(id, rawQName, qType, result, echoEdns);
            const canonical = buildDnsResponseBody(0, rawQName, qType, result, false);
            if (cKey) {
                DOH_GET_CACHE.set(cKey, { body: canonical, expire: Date.now() + DOH_GET_TTL });
                try {
                    await caches.default.put(`https://dns-cache/ech-v2/${qName}:${qType}`, new Response(canonical, {
                        headers: { 'Cache-Control': 'public, max-age=300, s-maxage=300' }
                    }));
                } catch (e) {}
            }
            const outBody = withDnsId(canonical, id);
            return dnsResponse(echoEdns ? appendOpt(outBody) : outBody, cacheable ? { 'X-Cache': 'DOH_MISS' } : null);
        }

        // Unmatched ordinary names in rule mode retain native HTTPS records.
        // Explicit best=true still permits the configured CDN ownership policy.
        if (qType === 65 && (!config.enhance || config.enhance === 'off' ||
            (config.enhance === 'rule' && config.best !== 'true' && !(await matchRule(qName, config))))) {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }

        const resolved = await resolveDNS(qName, qType === 28 ? 'AAAA' : (qType === 65 ? 'HTTPS' : 'A'), config, clientIP);
        if (resolved.error) return forwardQuery(rawBuffer);
        return dnsResponseFromResult(id, rawQName, qType, resolved, echoEdns);
    } catch (e) {
        console.error(e);
        return forwardQuery(rawBuffer);
    }
}

function buildDnsResponseBody(id, qName, qType, result, echoEdns = false) {
    if (qType === 65) {
        const rdata = result.httpsRecord ? [result.httpsRecord] : [];
        return createMultiAnsResponse(id, qName, 65, rdata, rdata.length ? (result.ttl ?? 300) : 60, echoEdns, result.rcode || 0);
    }
    const bytes = qType === 28 ? ipv6ToBytes : ipToBytes;
    const answers = (result.answers || []).map(bytes).filter(Boolean);
    return createMultiAnsResponse(id, qName, qType, answers, result.ttl ?? 300, echoEdns, result.rcode || 0);
}

function dnsResponseFromResult(id, qName, qType, result, echoEdns = false) {
    return dnsResponse(buildDnsResponseBody(id, qName, qType, result, echoEdns));
}

// ===================== JSON API =====================
// 预计算静态域名的标准响应（避免重复 JSON 序列化）
const STATIC_RESPONSE_CACHE = new Map();
const STATIC_RESPONSE_TTL = 300000; // 5分钟

// 判定是否可安全缓存：静态域名(CF/META)返回固定优选IP，不依赖客户端位置(ECS)，
// 因此无需 clientIp 参与；但任何自定义覆盖参数都会改变响应内容，必须排除。
function isCacheableStaticRequest(domain, config, type) {
    // Only fixed address policy can use a domain/type-only cache. HTTPS/ECH and other RRsets may expire independently or vary by ECS.
    if (type !== 'A' && type !== 'AAAA') return false;
    if (isCNDomain(domain)) return false;
    const isStaticCF = CF_STATIC_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
    const isStaticMeta = META_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
    if (!isStaticCF && !isStaticMeta) return false;
    if (config.enhance && config.enhance !== 'off') return false;
    // 以下自定义参数会改变响应内容 → 不缓存（避免缓存键碰撞）
    if (config.ip4 || config.ip6 || config.metaIp4 || config.metaIp6) return false;
    if (config.cfDomain || config.metaDomain || config.sub) return false;
    if (config.area || config.exclude) return false;
    if (config.best === 'true' || config.shuffle === 'false') return false;
    if (config.no6 === 'true') return false;          // no6=true 屏蔽AAAA
    if (config.nocf6 === 'false') return false;       // nocf6=false 放行CF IPv6
    if (config.alpn !== 'h3,h2') return false;        // alpn 影响 HTTPS 记录
    if (config.mandatory !== 'alpn') return false;    // mandatory 影响 HTTPS 记录
    // ech 决定注入哪份 ECHConfig（buildHttpsRecord 使用 config.echDomain）。
    // 若漏判，任意人可用 ?ech=<自己的域名> 把自定义 ECH 写进静态域名的共享缓存，
    // 之后所有用户拿到的 chatgpt.com/github.com 等 HTTPS RR 都会带攻击者的 ECH 配置。
    if (config.echDomain !== 'cloudflare-ech.com') return false;
    // 静态 META 域名未显式指定 metaIp4/metaIp6 时（DEFAULT_META_IP 为空），
    // A/AAAA 与 HTTPS hints 来自带 ECS 的实时上游查询，结果与访问者网段相关，不可跨用户共享。
    if (isStaticMeta && !config.metaIp4 && !config.metaIp6) return false;
    return true;
}

async function handleApiQuery(url, clientIP, env) {
    const domain = url.searchParams.get('domain')?.toLowerCase().replace(/\.$/, '');
    const type = url.searchParams.get('type')?.toUpperCase() || 'A';
    if (!domain) return json({ error: '缺少 domain' }, 400);
    if (!['A', 'AAAA', 'HTTPS', 'CNAME', 'TXT', 'MX', 'NS'].includes(type)) return json({ error: '类型不支持' }, 400);
    const config = buildConfig(url);
    if (!config.clientIp) config.clientIp = clientIP;
    if (config.enhance !== 'balanced') await applySubConfig(config, env);

    // 静态域名 + 默认参数 = 可缓存预计算响应（结果不依赖 clientIp/ECS）
    const cacheable = isCacheableStaticRequest(domain, config, type);
    
    // 提前声明 cacheKey，避免作用域问题
    const cacheKey = cacheable ? `v2:${domain}:${type}` : null;

    if (cacheable) {
        const cached = STATIC_RESPONSE_CACHE.get(cacheKey);
        if (cached && Date.now() < cached.expire) {
            return new Response(cached.body, {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Cache-Control': `public, max-age=${type === 'HTTPS' ? 600 : 300}, s-maxage=${type === 'HTTPS' ? 600 : 300}`,
                    'Vary': 'Accept-Encoding',
                    'X-Cache': 'STATIC_HIT'
                }
            });
        }
        // 二级回退：跨 isolate 共享缓存 (Cache API)，其他 isolate 已算过则直接复用
        try {
            const sharedRes = await caches.default.match(`https://dns-cache/static/${cacheKey}`);
            if (sharedRes) {
                const sharedBody = await sharedRes.text();
                STATIC_RESPONSE_CACHE.set(cacheKey, { body: sharedBody, expire: Date.now() + STATIC_RESPONSE_TTL });
                return new Response(sharedBody, {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Cache-Control': `public, max-age=${type === 'HTTPS' ? 600 : 300}, s-maxage=${type === 'HTTPS' ? 600 : 300}`,
                        'Vary': 'Accept-Encoding',
                        'X-Cache': 'STATIC_HIT'
                    }
                });
            }
        } catch (e) {}
    }

    try {
        const result = await resolveDNS(domain, type, config, config.clientIp);
        if (result.httpsRecord) delete result.httpsRecord;
        const maxAge = result.ttl ?? ((type === 'HTTPS') ? 600 : 300);
        const body = JSON.stringify(result);
        
        if (cacheable) {
            STATIC_RESPONSE_CACHE.set(cacheKey, { body, expire: Date.now() + STATIC_RESPONSE_TTL });
            try {
                await caches.default.put(`https://dns-cache/static/${cacheKey}`, new Response(body, {
                    headers: { 'Cache-Control': `public, max-age=${maxAge}, s-maxage=${maxAge}` }
                }));
            } catch (e) {}
        }
        
        return new Response(body, {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Cache-Control': cacheable ? `public, max-age=${maxAge}, s-maxage=${maxAge}` : 'no-store',
                'Vary': 'Accept-Encoding'
            }
        });
    } catch (e) {
        return json({ error: e.message }, 500);
    }
}

// ===================== 核心调度 =====================
async function resolveDNS(domain, type, config, clientIP) {
    domain = domain.toLowerCase().replace(/\.$/, '');
    if (config.enhance === 'balanced') {
        const domestic = balancedDomestic(domain);
        // Match wire routing without adding a client ECS that the wire path does not inject.
        let result = await resolveFallbackRecord(domain, type, '', domestic ? UPSTREAM_CN_JSON_LIST : BALANCED_INTL_JSON);
        if (domestic && result.rcode === 2) {
            result = await resolveFallbackRecord(domain, type, '', BALANCED_INTL_JSON);
            return { ...result, policy: 'balanced-fallback' };
        }
        return { ...result, policy: domestic ? 'balanced-domestic' : 'balanced-international' };
    }
    if (isNativeDirect(domain, config)) {
        const h3 = xHttp3Result(domain, type, config);
        if (h3) return h3;
        const pins = localDirectPins(domain, type, config);
        if (pins.length) return { domain, type, answers: pins, ech: null, rcode: 0, ttl: 30, policy: 'local-pins' };
        // Native addresses and HTTPS metadata, never random prefixes or generic CDN IPs.
        let result = await resolveFallbackRecord(domain, type, clientIP, DIRECT_JSON);
        if (result.rcode === 2) result = await resolveFallbackRecord(domain, type, clientIP);
        return { ...result, policy: 'native-direct' };
    }
    // 国内域名分流：直接返回国内上游原始解析结果
    if (!cnDomainSet) cnDomainSet = new Set(CN_DOMAIN_SUFFIXES);
    if (isCNDomain(domain)) {
        return await handleCNDomain(domain, type, config, clientIP);
    }
    const best = config.best === 'true';

    const isStaticCF = CF_STATIC_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
    const isStaticMeta = META_DOMAINS.some(d => domain === d || domain.endsWith("." + d));

    let owner = isStaticCF ? 'CF' : (isStaticMeta ? 'META' : null);

    const getOwner = async () => (await activeProbeOwner(domain, null, clientIP))?.owner || null;
    // CDN ownership alone is not permission to rewrite a third-party HTTPS record.
    if (!owner && best) owner = await getOwner();

    let effectiveCF = isStaticCF, effectiveMeta = isStaticMeta;
    if (!effectiveCF && !effectiveMeta && best) {
        const realOwner = owner;
        if (realOwner === 'CF') effectiveCF = true;
        else if (realOwner === 'META') effectiveMeta = true;
    }
// A/AAAA 处理    
    if (type === 'A' || type === 'AAAA') {
        const ruleObj = (config.enhance === 'rule' || config.enhance === 'full')
            ? await matchRule(domain, config) : null;
        if (isTypeBlocked(type, ruleObj, config, effectiveCF)) {
            return { domain, type, answers: [], ech: null };
        }
        if (ruleObj) {
            const ips = ruleObj.ips.filter(ip => type === 'AAAA' ? ip.includes(':') : !ip.includes(':'));
            if (ips.length) {
                return { domain, type, answers: config.shuffle !== 'false' ? shuffle(ips) : ips, ech: null };
            }
        }
    // 静态域名（含 best 提升）的优选 IP
    if (effectiveCF || effectiveMeta) {
        return handleStaticDomain(domain, type, config, effectiveCF, effectiveMeta, clientIP);
    }
    // 普通域名上游查询
    const dnsType = type === 'AAAA' ? 28 : 1;
    const data = await queryUpstreamDNS(domain, dnsType, clientIP);
    if (!data) return { domain, type, answers: [], ech: null, rcode: 2 };
    const answers = data?.Answer?.filter(r => r.type === dnsType).map(r => r.data) || [];
    // 透传上游 RCODE（3 = NXDOMAIN）；否则不存在的域名会被当成 NODATA 并缓存 300s
    return { domain, type, answers, ech: null, rcode: data.Status === 3 ? 3 : 0, ttl: upstreamAnswerTtl(data) };
    }
    // HTTPS 处理
    if (type === 'HTTPS') {
        // CF/Meta 域名
        if (owner === 'CF' || owner === 'META') {
            const usePreferredHints = isStaticCF || isStaticMeta || best;
            const result = await buildStaticHttpsRecord(domain, config, clientIP, owner === 'CF', owner === 'META', usePreferredHints);
            return cleanResult(result);
        }

        // 增强模式 (非CF/Meta)
        if (config.enhance === 'full' ||
            (config.enhance === 'rule' && await matchRule(domain, config))) {
            const result = await buildEnhancedHttpsRecord(domain, config, clientIP);
            return cleanResult(result);
        }
        // 默认返回上游原始 HTTPS 记录
        const data = await queryUpstreamDNS(domain, 65, clientIP);
        const result = { domain, type, answers: [] };
        if (data?.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecordFull(rec.data);  
                if (parsed) {
                    result.ech = parsed.ech || null;
                    if (parsed.ipv4hints && parsed.ipv4hints.length > 0) result.ipv4hints = parsed.ipv4hints;
                    if (parsed.ipv6hints && parsed.ipv6hints.length > 0) result.ipv6hints = parsed.ipv6hints;
                    result.alpn = parsed.alpn || '';
                }
            }
        }
        return result;
    }
    // 通用兜底：CNAME、TXT、MX 等所有其他类型
    return await resolveFallbackRecord(domain, type, clientIP);
}

function cleanResult(result) {
    if (result.ipv4hints && result.ipv4hints.length === 0) delete result.ipv4hints;
    if (result.ipv6hints && result.ipv6hints.length === 0) delete result.ipv6hints;
    return result;
}

// ===================== 静态域名 A/AAAA 处理 =====================
async function handleStaticDomain(domain, type, config, isCF, isMeta, clientIP) {
    const doShuffle = config.shuffle !== 'false';
    let ips = [];
    
    // ----- AAAA 记录 -----
    if (type === 'AAAA') {
        if (isDomainIpv4Only(domain)) return { domain, type, answers: [], ech: null };

        if (isMeta) {
            ips = config.metaIp6 ? parseIpList(config.metaIp6, doShuffle) : [];
        } else {
            // CF
            if (config.ip6) ips = parseIpList(config.ip6, doShuffle);
            else if (config.cfDomain) {
                const resolved = await resolveMultiDomainToIps(config.cfDomain, 28, clientIP, doShuffle, MAX_PRESCREEN);
                if (resolved.length > 0) ips = resolved.map(formatIPv6FromBytes);
            } else ips = parseIpList(DEFAULT_CF_IP6, doShuffle);
        }
    }

    // ----- A 记录 -----
    if (type === 'A') {
        if (isCF) {
            if (config.ip4) ips = parseIpList(config.ip4, doShuffle);
            else if (config.cfDomain) {
                const resolved = await resolveMultiDomainToIps(config.cfDomain, 1, clientIP, doShuffle, MAX_PRESCREEN);
                if (resolved.length > 0) ips = resolved.map(bytesToIp);
            } else ips = parseIpList(DEFAULT_CF_IP, doShuffle);
        } else {
            // Meta
            if (config.metaIp4) ips = parseIpList(config.metaIp4, doShuffle);
            else if (config.metaDomain) {
                const resolved = await resolveMultiDomainToIps(config.metaDomain, 1, clientIP, doShuffle, MAX_PRESCREEN);
                if (resolved.length > 0) ips = resolved.map(bytesToIp);
            } else ips = parseIpList(DEFAULT_META_IP, doShuffle);
        }
    }

    // ----- 通用安全兜底：如果最终 IP 列表为空且未被屏蔽，从上游获取真实记录 -----
    if (ips.length === 0) {
        const ruleObj = (config.enhance === 'rule' || config.enhance === 'full')
            ? await matchRule(domain, config)
            : null;
        if (!isTypeBlocked(type, ruleObj, config, isCF)) {
            const dnsType = type === 'AAAA' ? 28 : 1;
            const real = await resolveRealHints(domain, dnsType, clientIP);
            if (real.length > 0) {
                ips = real;
                if (doShuffle) ips = shuffle(ips);
            }
        }
    }
    if(ips.length > MAX_FINAL){
        if(doShuffle) ips = shuffle([...ips]);
        ips = ips.slice(0, MAX_FINAL);
    }
    return { domain, type, answers: ips, ech: null };
}
// ===================== CN域名处理 =====================
async function handleCNDomain(domain, type, config, clientIP) {
    // 获取增强规则对象（仅增强模式开启时）
    const ruleObj = (config.enhance === 'rule' || config.enhance === 'full')
        ? await matchRule(domain, config)
        : null;

    // 1. 检查屏蔽（复用 isTypeBlocked）
    if (isTypeBlocked(type, ruleObj, config, false)) {
        return { domain, type, answers: [], ech: null };
    }

    // 2. 规则提供了对应类型的 IP → 直接返回规则 IP
    if (ruleObj) {
        if (type === 'A' && ruleObj.ips.some(ip => !ip.includes(':'))) {
            let ips = ruleObj.ips.filter(ip => !ip.includes(':'));
            if (config.shuffle !== 'false') ips = shuffle(ips);
            return { domain, type, answers: ips, ech: null };
        }
        if (type === 'AAAA' && ruleObj.ips.some(ip => ip.includes(':'))) {
            let ips = ruleObj.ips.filter(ip => ip.includes(':'));
            if (config.shuffle !== 'false') ips = shuffle(ips);
            return { domain, type, answers: ips, ech: null };
        }
    }

    // 3. 未匹配规则或无IP，走国内兜底（查询国内上游返回原始记录）
    return await resolveFallbackRecord(domain, type, clientIP, UPSTREAM_CN_JSON_LIST);
}

//=====================公共 HTTPS 记录构建函数=====================    
async function buildHttpsRecord(domain, config, clientIP, options = {}) {
    const {
        isCF = false,
        isMeta = false,
        usePreferredHints = true,
        injectECH = false,
        injectEnhance = false
    } = options;

    const alpn = config.alpn || 'h3,h2';
    const owner = isCF ? 'CF' : (isMeta ? 'META' : null);
    const mode = config.enhance || 'off';
    const ruleObj = (mode === 'rule' || mode === 'full') ? await matchRule(domain, config) : null;

    let ipv4 = [], ipv6 = [];

    // 1. 收集 hints
    if (ruleObj) {
        if (ruleObj.ips.length > 0) {
            ipv4 = ruleObj.ips.filter(ip => !ip.includes(':'));
            ipv6 = ruleObj.ips.filter(ip => ip.includes(':'));
        } else if (owner) {
            const source = usePreferredHints ? 'preferred' : 'real';
            const hints = await collectIpHints(domain, config, clientIP, owner, source);
            ipv4 = hints.ipv4;
            ipv6 = hints.ipv6;
        }
    } else if (owner) {
        const source = usePreferredHints ? 'preferred' : 'real';
        const hints = await collectIpHints(domain, config, clientIP, owner, source);
        ipv4 = hints.ipv4;
        ipv6 = hints.ipv6;
    } else {
        const hints = await collectIpHints(domain, config, clientIP, null, mode);
        ipv4 = hints.ipv4;
        ipv6 = hints.ipv6;
    }

    // 2. Apply the same address policy to hints and fallback, including CDN IPv4-only.
    const block4 = isTypeBlocked('A', ruleObj, config, isCF);
    const block6 = (owner && isDomainIpv4Only(domain)) || isTypeBlocked('AAAA', ruleObj, config, isCF);
    if (block4) ipv4 = [];
    if (block6) ipv6 = [];

    // 3. 安全兜底
    if (ipv4.length === 0 && !block4) {
        ipv4 = await resolveRealHints(domain, 1, clientIP);
    }
    if (ipv6.length === 0 && !block6) {
        ipv6 = await resolveRealHints(domain, 28, clientIP);
    }

    // 4. 构建参数表
    const paramMap = new Map();
    let ttl = 300;
    let echSource;

    if (!owner || injectEnhance) {
        try {
            const data = await queryUpstreamDNS(domain, 65, clientIP);
            if (data?.Answer) {
                const rec = data.Answer.find(r => r.type === 65);
                if (rec) {
                    ttl = Math.min(ttl, upstreamAnswerTtl(data, ttl));
                    const upstreamParams = parseRawHttpsRecord(rec.data);
                    for (const p of upstreamParams) {
                        if (p.key && p.val !== undefined) paramMap.set(p.key, p.val);
                    }
                }
            }
        } catch (e) {}
    }

    // 5. 注入 ECH
    if (injectECH && owner) {
        const info = isCF
            ? await fetchRealEch(config.echDomain || 'cloudflare-ech.com', clientIP)
            : await fetchMetaEch(domain, clientIP);
        if (info?.ech) {
            paramMap.set('ech', info.ech);
            echSource = info.legacy ? 'legacy-meta' : 'dns';
            ttl = Math.min(ttl, info.ttl);
        } else {
            // Do not hold an ECH-less fallback for the normal synthetic lifetime.
            ttl = Math.min(ttl, 60);
        }
    }

    // 6. 设置 ALPN 与 hints（仅非空时写入）
    paramMap.set('alpn', alpn);
    if (ipv4.length > 0) paramMap.set('ipv4hint', ipv4.join(','));
    else paramMap.delete('ipv4hint');
    if (ipv6.length > 0) paramMap.set('ipv6hint', ipv6.join(','));
    else paramMap.delete('ipv6hint');

    // 7. 注入增强默认参数
    const finalParams = Array.from(paramMap, ([k, v]) => ({ key: k, val: v }));
    if (injectEnhance) {
        injectEnhanceDefaults(finalParams, config.mandatory || 'alpn');
    }

    return { ...buildHttpsRecordFromParams(domain, finalParams, ipv4, ipv6), ttl, ...(echSource ? { echSource } : {}) };
}

// ===================== HTTPS 记录构建 (CF/Meta) =====================
async function buildStaticHttpsRecord(domain, config, clientIP, isCF, isMeta, usePreferredHints) {
    return buildHttpsRecord(domain, config, clientIP, {
        isCF,
        isMeta,
        usePreferredHints,
        injectECH: true,
        injectEnhance: false
    });
}

// ===================== HTTPS 记录增强构建(非CF/Meta) =====================
async function buildEnhancedHttpsRecord(domain, config, clientIP) {
    return buildHttpsRecord(domain, config, clientIP, {
        injectECH: false,
        injectEnhance: true
    });
}

// ===================== 统一 IP hints 收集 =====================
async function collectIpHints(domain, config, clientIP, owner, source) {
    let ipv4 = [], ipv6 = [];

    // 规则匹配 (rule/full 优先)
    if (source === 'rule' || source === 'full') {
        const ruleObj = await matchRule(domain, config);
        if (ruleObj !== null) {
            const matchedIPs = ruleObj.ips;
            ipv4 = matchedIPs.filter(ip => !ip.includes(':'));
            ipv6 = matchedIPs.filter(ip => ip.includes(':'));
            // 匹配到域名但 IP 为空时从上游获取
            if (ipv4.length === 0 && ipv6.length === 0) {
                [ipv4, ipv6] = await Promise.all([
                    resolveRealHints(domain, 1, clientIP),   // 在第二部分
                    resolveRealHints(domain, 28, clientIP)
                ]);
            }
        }
    }

    // 优选 IP (preferred)
    if (source === 'preferred') {
        if (owner === 'CF') {
            ipv4 = config.ip4 ? parseIpList(config.ip4, false) :
                config.cfDomain ? (await resolveMultiDomainToIps(config.cfDomain, 1, clientIP, false, MAX_PRESCREEN)).map(bytesToIp) :
                parseIpList(DEFAULT_CF_IP, false);
            ipv6 = !isDomainIpv4Only(domain) ?
                (config.ip6 ? parseIpList(config.ip6, false) :
                config.cfDomain ? (await resolveMultiDomainToIps(config.cfDomain, 28, clientIP, false, MAX_PRESCREEN)).map(formatIPv6FromBytes) :
                parseIpList(DEFAULT_CF_IP6, false)) : [];
        } else {
            ipv4 = config.metaIp4 ? parseIpList(config.metaIp4, false) :
                config.metaDomain ? (await resolveMultiDomainToIps(config.metaDomain, 1, clientIP, false, MAX_PRESCREEN)).map(bytesToIp) :
                parseIpList(DEFAULT_META_IP, false);
            ipv6 = config.metaIp6 ? parseIpList(config.metaIp6, false) :
                config.metaDomain ? (await resolveMultiDomainToIps(config.metaDomain, 28, clientIP, false, MAX_PRESCREEN)).map(formatIPv6FromBytes) : [];
        }
    }

    // 真实 IP (real / full 且未匹配)
    if ((source === 'real' || source === 'full') && ipv4.length === 0 && ipv6.length === 0) {
        [ipv4, ipv6] = await Promise.all([
            resolveRealHints(domain, 1, clientIP),
            resolveRealHints(domain, 28, clientIP)
        ]);
    }

    ipv4 = [...new Set(ipv4)].slice(0, MAX_FINAL);
    ipv6 = [...new Set(ipv6)].slice(0, MAX_FINAL);
    if (config.shuffle !== 'false') {
        ipv4 = shuffle(ipv4);   
        ipv6 = shuffle(ipv6);
    }
    return { ipv4, ipv6 };
}
// ===================== 规则匹配 =====================

let builtinRulesMap = null;
let builtinRulesRefreshAt = 0;
let builtinRulesRefreshing = false;

function staticBuiltinRules() {
    const map = new Map();
    for (const group of BUILTIN_HINTS) {
        if (!group.domains) continue;
        const { ips = [], noA = false, noAAAA = false } = group;
        for (const domain of group.domains) map.set(domain, { ips, noA, noAAAA });
    }
    return map;
}

async function getBuiltinRulesMap() {
    if (builtinRulesRefreshing) return builtinRulesMap || staticBuiltinRules();
    if (builtinRulesMap && Date.now() < builtinRulesRefreshAt) return builtinRulesMap;
    builtinRulesRefreshing = true;
    let retry = false;
    let nextRefresh = Date.now() + HOSTS_CACHE_TTL;
    try {
    const map = new Map();
    const hints = BUILTIN_HINTS;
    if (Array.isArray(hints)) {
        // 第一遍：处理 hosts 条目，生成基础规则
        for (const group of hints) {
            if (group.hosts && Array.isArray(group.hosts)) {
                const noA = group.noA || false;
                const noAAAA = group.noAAAA || false;
                const hostIpsMap = new Map();
                for (const url of group.hosts) {
                    let data = null;
                    const cacheKey = `https://dns-cache/hosts-v2/${encodeURIComponent(url)}`;
                    const cached = hostsCache.get(url);

                    // 1. 内存缓存命中
                    if (cached && Date.now() < cached.expire) {
                        data = cached.data;
                    } else {
                        // 2. Cache API 读取（新增）
                        const cachedText = await readCache(cacheKey);
                        if (cachedText) {
                            try {
                                const entry = JSON.parse(cachedText);
                                if (Array.isArray(entry.data) && entry.expire > Date.now()) {
                                    data = entry.data;
                                    hostsCache.set(url, entry);
                                }
                            } catch (e) {
                                data = null;
                            }
                        }    
                        // 3. Cache API 未命中，远程下载（原逻辑）
                        if (!data) {
                            try {
                                data = await fetchWithTimeout(url, {}, 5000, async res => {
                                    if (!res.ok) throw new Error('hosts HTTP error');
                                    const result = await res.json();
                                    if (!Array.isArray(result)) throw new Error('invalid hosts list');
                                    return result;
                                });
                                const entry = { data, expire: Date.now() + HOSTS_CACHE_TTL };
                                hostsCache.set(url, entry);
                                await writeCache(cacheKey, JSON.stringify(entry), HOSTS_CACHE_TTL / 1000);
                            } catch (e) {
                                retry = true;
                                if (cached) data = cached.data;
                            }
                        }
                    }

                    const stored = hostsCache.get(url);
                    if (stored?.expire > Date.now()) nextRefresh = Math.min(nextRefresh, stored.expire);
                    if (data && Array.isArray(data)) {
                        for (const entry of data) {
                            let domain, ip;
                            if (typeof entry === 'object' && !Array.isArray(entry)) {
                                domain = entry.domain || entry.host || '';
                                ip = entry.ip || entry.addr || '';
                            } else if (Array.isArray(entry) && entry.length >= 2) {
                                ip = entry[0];
                                domain = entry[1];
                            }
                            if (domain && ip) {
                                if (!hostIpsMap.has(domain)) hostIpsMap.set(domain, new Set());
                                hostIpsMap.get(domain).add(ip);
                            }
                        }
                    }
                }

                for (const [domain, ipSet] of hostIpsMap.entries()) {
                    const ips = Array.from(ipSet);
                    map.set(domain, { ips, noA, noAAAA });
                }
            }
        }

        // 第二遍：处理普通条目（可覆盖 hosts 生成的规则）
        for (const group of hints) {
            if (group.domains && Array.isArray(group.domains)) {
                const { ips = [], noA = false, noAAAA = false } = group;
                const ruleObj = { ips, noA, noAAAA };
                for (const d of group.domains) {
                    map.set(d, ruleObj);
                }
            }
        }
    } else {
        for (const [domain, val] of Object.entries(hints)) {
            map.set(domain, {
                ips: Array.isArray(val) ? val : (val.ips || []),
                noA: val.noA || false,
                noAAAA: val.noAAAA || false
            });
        }
    }
    builtinRulesMap = map;
    builtinRulesRefreshAt = retry ? Date.now() + 60_000 : nextRefresh;
    return map;
    } finally { builtinRulesRefreshing = false; }
}

async function matchRule(domain, config) {
   
    const builtin = await getBuiltinRulesMap();
    const user = config.rules ? parseRules(config.rules) : null;
    // Exact match first, then longest suffix; user entries override the same pattern.
    let winner = user?.get(domain) || builtin.get(domain);
    if (!winner) {
        for (let name = domain; name;) {
            const pattern = '*.' + name;
            winner = user?.get(pattern) || builtin.get(pattern);
            if (winner) break;
            const dot = name.indexOf('.');
            if (dot < 0) break;
            name = name.slice(dot + 1);
        }
    }
    if (!winner) return null;
    return { ...winner, ips: winner.ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]) };
}

function matchDomainPattern(domain, pattern) {
    if (pattern.startsWith('*.')) {
        const suffix = pattern.substring(1);
        return domain.endsWith(suffix) || domain === suffix.substring(1);
    }
    return domain === pattern;
}

function parseRules(rulesStr) {
    const map = new Map();
    if (!rulesStr) return map;
    const entries = rulesStr.split(';');
    for (const entry of entries) {
        const colonIdx = entry.indexOf(':');
        if (colonIdx === -1) continue;
        const patternPart = entry.substring(0, colonIdx).trim();    // 可能是 "*.google.com" 或 "*.google.com,google.com"
        const rest = entry.substring(colonIdx + 1).trim();

        const dashIdx = rest.indexOf('-');
        let ips = [];
        let flags = new Set();

        if (dashIdx === -1) {
            ips = rest.split(',').map(s => s.trim()).filter(s => s);
            ips = ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]); 
        } else {
            const ipPart = rest.substring(0, dashIdx).trim();
            const flagPart = rest.substring(dashIdx + 1).trim();
            if (ipPart) {
                ips = ipPart.split(',').map(s => s.trim()).filter(s => s);
                ips = ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]); 
            }
            if (flagPart) {
                flagPart.split('-').map(s => s.trim().toLowerCase()).forEach(f => {
                    if (f === 'noa' || f === 'noaaaa') flags.add(f);
                });
            }
        }

        const ruleObj = { ips, noA: flags.has('noa'), noAAAA: flags.has('noaaaa') };

        // 处理多域名：用逗号分隔，每个域名都对应同样的规则
        const patterns = patternPart.split(',').map(s => s.trim()).filter(s => s);
        for (const pattern of patterns) {
            map.set(pattern, ruleObj);
        }
    }
    return map;
}

// ===================== HTTPS 记录打包 =====================
function buildHttpsRecordFromParams(domain, params, ipv4Hints, ipv6Hints) {
    const finalParams = sortAndDedupeParams([...params], ipv4Hints, ipv6Hints);
    const httpsRecord = packHttpsParams(1, ".", finalParams);   // packHttpsParams 在第二部分
    const result = { domain, type: 'HTTPS', answers: [] };
    result.ech = finalParams.find(p => p.key === 'ech')?.val || null;
    result.httpsRecord = httpsRecord;
    if (ipv4Hints.length) result.ipv4hints = ipv4Hints;
    if (ipv6Hints.length) result.ipv6hints = ipv6Hints;
    return result;
}

function sortAndDedupeParams(params, ipv4Hints, ipv6Hints) {
    const keyOrder = {
        mandatory: SVC_PARAM_IDS.mandatory,
        alpn: SVC_PARAM_IDS.alpn,
        "no-default-alpn": SVC_PARAM_IDS["no-default-alpn"],
        port: SVC_PARAM_IDS.port,
        ipv4hint: SVC_PARAM_IDS.ipv4hint,
        ech: SVC_PARAM_IDS.ech,
        ipv6hint: SVC_PARAM_IDS.ipv6hint
    };
    const map = new Map();
    const booleanKeys = new Set(['no-default-alpn']);

    for (const p of params) {
        if (p.key && p.val !== undefined) {
            if (p.val !== '' || booleanKeys.has(p.key)) {
                map.set(p.key, p.val);
            }
        }
    }

    if (ipv4Hints.length > 0) map.set('ipv4hint', ipv4Hints.join(','));
    else map.delete('ipv4hint');
    if (ipv6Hints.length > 0) map.set('ipv6hint', ipv6Hints.join(','));
    else map.delete('ipv6hint');

    const sortedKeys = Array.from(map.keys()).sort(
        (a, b) => (keyOrder[a] ?? 999) - (keyOrder[b] ?? 999)
    );
    return sortedKeys.map(k => ({ key: k, val: map.get(k) }));
}

// ===================== 假名 ECH 响应 =====================
async function buildFakeEchResponse(config, domain, clientIP, isCF) {
    const owner = isCF ? 'CF' : 'META';
    const { ipv4, ipv6 } = await collectIpHints(domain, config, clientIP, owner, 'preferred');
    const info = isCF ? await fetchRealEch(config.echDomain || 'cloudflare-ech.com', clientIP) : await fetchMetaEch('www.facebook.com', clientIP);
    if (!info?.ech) return { domain, type: 'HTTPS', answers: [], rcode: 2, ttl: 0 };
    const params = [
        { key: 'alpn', val: config.alpn || 'h3,h2' },
        { key: 'ech', val: info.ech }
    ];
    return { ...buildHttpsRecordFromParams(domain, params, ipv4, ipv6), ttl: Math.min(300, info.ttl) };
}

// ===================== 第二部分：工具函数 =====================
/**
 * IP 列表解析（支持逗号分隔或 JSON 数组）
 * @param {string} raw - 原始字符串
 * @param {boolean} doShuffle - 是否随机乱序（默认 true）
 * @returns {string[]} IP 数组
 */
function parseIpList(raw, doShuffle = true) {
    if (!raw) return [];
    raw = raw.trim();
    let arr;
    if (raw.startsWith('[') && raw.endsWith(']')) {
        try {
            arr = JSON.parse(raw).map(String).filter(s => s);
        } catch {
            arr = raw.split(',').map(s => s.trim()).filter(s => s);
        }
    } else {
        arr = raw.split(',').map(s => s.trim()).filter(s => s);
    }
    if (doShuffle) return shuffle(arr);
    return arr;
}
/**
 * cacheAPI R&W
 */
async function readCache(cacheKey) {
    try {
        const res = await caches.default.match(cacheKey);
        if (res) return await res.text();
    } catch (e) {}
    return null;
}
async function writeCache(cacheKey, text, ttlSeconds) {
    try {
        const response = new Response(text, {
            headers: { 'Cache-Control': `public, max-age=${ttlSeconds}, s-maxage=${ttlSeconds}` }
        });
        await caches.default.put(cacheKey, response);
    } catch (e) {}
}

/**
 * 记录预筛选函数
 */
function prescreenIpList(raw) {
    if (!raw) return '';
    // JSON 数组形式必须先解析再抽样，否则按逗号切分会残留引号与方括号，
    // 后续 ipToBytes 得到 [0]，静默返回畸形 A 记录。
    const isJson = raw.trim().startsWith('[') && raw.trim().endsWith(']');
    let ips;
    if (isJson) {
        try { ips = JSON.parse(raw).map(String).map(s => s.trim()).filter(s => s); }
        catch { ips = raw.split(',').map(s => s.trim().replace(/^[\s"']+|[\s"']+$/g, '')).filter(s => s); }
    } else {
        ips = raw.split(',').map(s => s.trim()).filter(s => s);
    }
    if (ips.length <= MAX_PRESCREEN) return raw;
    const picked = shuffle([...ips]).slice(0, MAX_PRESCREEN);
    return isJson ? JSON.stringify(picked) : picked.join(',');
}
/**
 * HTTPS RR 注入参数
 */
function injectEnhanceDefaults(params, mandatoryValue) {
    const existingKeys = new Set(params.map(p => p.key));
    if (existingKeys.has('mandatory')) return;
    // RFC9460 §8：mandatory 列出记录中不存在的键时，客户端必须忽略整条 HTTPS 记录。
    // 必须与本记录实际存在的参数取交集（如 ?mandatory=port 但记录无 port 时不应写入）。
    const val = (mandatoryValue || 'alpn')
        .split(',').map(s => s.trim()).filter(k => k && existingKeys.has(k)).join(',');
    if (val) params.push({ key: 'mandatory', val });
  //  if (!existingKeys.has('no-default-alpn')) params.push({ key: 'no-default-alpn', val: '' });
}

/**
 * 日志系统
 */
async function handleLogsRequest() {
    try {
        // 确保 workerStartTime 只初始化一次（惰性初始化，且防止无效值）
        if (!globalThis.__workerStartTime || globalThis.__workerStartTime < 1000000000000) {
            globalThis.__workerStartTime = Date.now();
        }
        await ensureCNDomainSet();
        const now = Date.now();

        // 辅助：毫秒时间戳 → 东八区 ISO 字符串
        const toBeijingTime = (ts) => {
            if (!ts) return null;
            const d = new Date(ts);
            const offset = 8 * 60; // 东八区偏移分钟数
            const local = new Date(d.getTime() + offset * 60 * 1000);
            return local.toISOString().replace('Z', '+08:00');
        };

        // ==================== Worker 运行信息 ====================
        // 使用顶层常量 workerStartTime，若未初始化则用当前时间兜底
        const startTime = globalThis.__workerStartTime;
        const uptimeMs = now - startTime;
        const uptimeSeconds = Math.floor(uptimeMs / 1000);
        const hours = Math.floor(uptimeSeconds / 3600);
        const minutes = Math.floor((uptimeSeconds % 3600) / 60);
        const seconds = uptimeSeconds % 60;
        const uptimeFormatted = `${hours}h ${minutes}m ${seconds}s`;

        const runtime = {
            _description: 'Worker 运行信息',
            uptime: uptimeFormatted,
            startedAt: toBeijingTime(startTime),
        };

        // ==================== 国内域名列表 (CN List) ====================
        const cnList = {
            _description: '国内域名列表加载状态',
            domainCount: cnDomainSet ? cnDomainSet.size : 0,
            lastFetch: cnDomainLastFetch ? toBeijingTime(cnDomainLastFetch) : null,
            nextFetchIn: cnDomainLastFetch
                ? Math.max(0, CN_DOMAIN_CACHE_TTL - (now - cnDomainLastFetch)) / 1000 + 's'
                : 'expired',
            sourceUrl: CN_DOMAIN_LIST_URL,
            ttl: CN_DOMAIN_CACHE_TTL / 1000 / 3600 + '小时',
        };

        // ==================== 缓存状态 ====================
        const echKey = 'ech:cloudflare-ech.com';
        const cacheStatus = {
            _description: '内存 & Cache API 双重缓存状态',
            memory: {
                echCache: cacheMap.has(echKey) ? '已预热 (warm)' : '未预热 (cold)',
                ownerCacheSize: cacheMap.size,
                subCacheCount: subCache.size,
                hostsCacheCount: hostsCache.size,
                prefixCacheCount: prefixCache.size,
            },
            edgeCache: {
                ech: cacheMap.has(echKey) ? '已缓存 (cached)' : '未缓存 (empty)',
                sub: subCache.size > 0 ? '已缓存 (cached)' : '未缓存 (empty)',
                cn: cnDomainSet && cnDomainSet.size > 1000 ? '已缓存 (cached)' : '未缓存 (empty)',
                hosts: hostsCache.size > 0 ? '已缓存 (cached)' : '未缓存 (empty)',
            }
        };

        // 订阅缓存详情（脱敏：订阅链接常内嵌 token/密钥，/log 是公开端点）
        const maskUrl = (u) => {
            try {
                const x = new URL(u);
                return x.origin + '/<redacted>';
            } catch {
                return '<redacted>';
            }
        };
        const subDetails = [];
        for (const [url, entry] of subCache.entries()) {
            subDetails.push({
                url: maskUrl(url),
                cachedAt: toBeijingTime(entry.expire - SUB_CACHE_TTL),
                expiresIn: Math.max(0, (entry.expire - now) / 1000).toFixed(0) + 's',
                contentLength: entry.content ? entry.content.length : 0,
            });
        }

        // ==================== 组装最终响应 ====================
        const payload = {
            timestamp: toBeijingTime(now),
            runtime: runtime,
            cnList: cnList,
            caches: cacheStatus,
            subCache: subDetails,
        };

        return json(payload);
    } catch (e) {
        // 捕获异常并返回错误信息，方便定位
        // Do not reveal internal error messages on the administrative endpoint.
        return json({ error: 'log handler failed' }, 500);
    }
}
/**
 * Fisher-Yates 洗牌算法
 */
function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

/**
 * 多域名并发解析 IP，支持洗牌
 */
async function resolveMultiDomainToIps(domainsStr, type, clientIP, doShuffle = true, limit = 0) {
    const domains = domainsStr.split(',').map(s => s.trim()).filter(s => s);
    if (domains.length === 0) return [];
    const promises = domains.map(d => resolveDomainToIp(d, type, clientIP));
    const results = await Promise.allSettled(promises);
    const allIps = new Set();
    for (const res of results) {
        if (res.status === 'fulfilled') {
            for (const ip of res.value) allIps.add(ip);
        }
    }
    let ipArray = Array.from(allIps);
    if (doShuffle) shuffle(ipArray);
    if(limit >0 && ipArray.length > limit){
        ipArray = ipArray.slice(0,limit);
    }
    if (type === 1) return ipArray.map(ipToBytes).filter(Boolean);
    else return ipArray.map(ipv6ToBytes).filter(Boolean);
}

/**
 * 解析单个域名的指定类型记录
 */
async function resolveDomainToIp(domain, type = 1, clientIP) {
    const data = await queryUpstreamDNS(domain, type, clientIP);
    if (data && data.Answer) {
        return data.Answer.filter(r => r.type === type).map(r => r.data);
    }
    return [];
}

/**
 * 带超时的 fetch：避免单个上游挂起拖垮竞速（超时视为失败，交给 Promise.any 切换）
 * 优化：2s 快速超时，减少等待时间
 */
async function fetchWithTimeout(url, init = {}, timeoutMs = 2000, consume = response => response) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await consume(await fetch(url, { ...init, signal: controller.signal }));
    } finally {
        clearTimeout(timer);
    }
}

/**
 * 上游 DNS 查询（带 ECS 支持与 Edge 缓存）
 */
// Canonical ECS prefixes: never send the full client address to upstreams.
function ecsPrefix(clientIP) {
    if (!clientIP) return '';
    const ip = String(clientIP).trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        const bytes = ipToBytes(ip);
        if (!bytes) return '';
        bytes[3] = 0;
        return bytesToIp(bytes) + '/24';
    }
    if (!ip.includes(':')) return '';
    try {
        const bytes = ipv6ToBytes(ip);
        if (!bytes) return '';
        bytes.fill(0, 7);
        return formatIPv6(bytes) + '/56';
    } catch { return ''; }
}

function upstreamAnswerTtl(data, cap = 300) {
    // Negative answers require SOA-derived TTL; do not cache them blindly.
    if (data?.Status !== 0 || !data.Answer?.length) return 0;
    const ttls = data.Answer.map(r => r.TTL);
    if (ttls.some(t => !Number.isInteger(t) || t < 0)) return 0;
    return Math.min(cap, ...ttls);
}

async function queryUpstreamDNS(name, type, clientIP = '', upstreamUrl = null, preferEch = false) {
    name = name.toLowerCase().replace(/\.$/, '');
    const params = new URLSearchParams({ name, type: String(type) });
    const prefix = ecsPrefix(clientIP);
    if (prefix) params.set('edns_client_subnet', prefix);
    const upstreamList = upstreamUrl
        ? (Array.isArray(upstreamUrl) ? upstreamUrl : [upstreamUrl])
        : UPSTREAM_JSON_LIST;
    // Different upstream policies and ECH selection semantics must not share cached answers.
    const scope = encodeURIComponent(upstreamList.join('|'));
    const cacheKey = new Request(`https://dns-cache/upstream-v2/${scope}/${encodeURIComponent(name)}/${type}/${encodeURIComponent(prefix || 'none')}/${preferEch ? 'ech' : 'rr'}`);
    try {
        if (typeof caches !== 'undefined' && caches.default) {
            const cachedRes = await caches.default.match(cacheKey);
            if (cachedRes) {
                const stored = Number(cachedRes.headers.get('X-DNS-Stored-At'));
                const data = await cachedRes.json();
                const age = Math.max(0, Math.floor((Date.now() - stored) / 1000));
                if (stored > 0 && isUsableDnsJson(data, type, name) && upstreamAnswerTtl(data, type === 65 ? 600 : 300) > age) {
                    return { ...data, Answer: data.Answer.map(r => ({ ...r, TTL: Math.max(0, r.TTL - age) })) };
                }
            }
        }
    } catch {}

    let result;
    try {
        result = await raceUpstreams(upstreamList, 'json', url =>
            fetchWithTimeout(url + '?' + params.toString(), { headers: { Accept: 'application/dns-json' } }, 2000, async res => {
                if (!res.ok) throw new Error('upstream HTTP error');
                const payload = await res.json();
                if (!isUsableDnsJson(payload, type, name)) throw new Error('invalid upstream DNS answer');
                return payload;
            }),
            data => preferredDnsAnswer(data, type, preferEch),
            (a, b) => !a || (a.Status === 3 && b.Status === 0) ? b : a);
    } catch {
        // Some JSON resolvers reject ECS. Retry the same upstream group without ECS;
        // the fallback uses its own no-ECS cache key and never changes domestic routing.
        return prefix ? queryUpstreamDNS(name, type, '', upstreamUrl, preferEch) : null;
    }

    const maxAge = preferEch && !result?.Answer?.some(r => r.type === 65 && parseHttpsRecord(r.data)?.ech)
        ? 0 : upstreamAnswerTtl(result, type === 65 ? 600 : 300);
    if (maxAge > 0 && typeof caches !== 'undefined' && caches.default) {
        try {
            await caches.default.put(cacheKey, new Response(JSON.stringify(result), {
                headers: { 'Cache-Control': `public, max-age=${maxAge}`, 'X-DNS-Stored-At': String(Date.now()) }
            }));
        } catch {}
    }
    return result;
}

// DNS JSON status 0=NOERROR, 3=NXDOMAIN; transient errors are not cacheable answers.
function isUsableDnsJson(data, type, requestedName) {
    if (!data || typeof data !== 'object' || ![0, 3].includes(data.Status)) return false;
    if (data.Answer !== undefined && !Array.isArray(data.Answer)) return false;
    // AliDNS returns a single Question object; DNSPod and Cloudflare use an array.
    if (data.Question !== undefined) {
        const questions = Array.isArray(data.Question) ? data.Question : [data.Question];
        if (questions.length !== 1) return false;
        const question = questions[0];
        if (!question || typeof question !== 'object' || String(question.name || '').toLowerCase().replace(/\.$/, '') !==
            requestedName.toLowerCase().replace(/\.$/, '') || Number(question.type) !== Number(type)) return false;
    }
    if (data.Answer?.some(a => !a || !Number.isInteger(a.type) || typeof a.data !== 'string')) return false;
    return true;
}

/**
 * 校验式竞速：并发请求所有上游，优先返回包含指定 DNS 类型记录的响应；
 * 若所有上游均无该类型记录，则返回第一个成功响应（保持兜底行为）。
 * 优化：找到有效响应立即 resolve，不等待其他上游。
 */
// Per-isolate, bounded health state for the configured upstreams only.
// Fast valid answers avoid unnecessary subrequests; a slow/failing or incomplete answer
// immediately or after a short hedge launches the next resolver.
const upstreamHealth = new Map();
function raceUpstreams(endpoints, kind, run, preferred, betterFallback = (a, b) => a ?? b) {
    const now = Date.now();
    const key = url => kind + ':' + url;
    const score = url => {
        const h = upstreamHealth.get(key(url));
        if (!h || now - h.updated > 60_000) return 150;
        return h.latency + h.failures * 250;
    };
    const ordered = [...endpoints].sort((a, b) => score(a) - score(b));
    return new Promise((resolve, reject) => {
        let next = 0, pending = 0, timer = null, done = false, fallback = null;
        function finish(value, error) {
            if (done) return;
            done = true;
            clearTimeout(timer);
            if (error) reject(error); else resolve(value);
        }
        function launch() {
            if (done || next >= ordered.length) return;
            clearTimeout(timer);
            const url = ordered[next++];
            const started = Date.now();
            pending++;
            const record = ok => {
                const old = upstreamHealth.get(key(url));
                const latency = Math.max(1, Date.now() - started);
                upstreamHealth.set(key(url), {
                    latency: old ? old.latency * 0.75 + latency * 0.25 : latency,
                    failures: ok ? 0 : Math.min(4, (old?.failures || 0) + 1),
                    updated: Date.now()
                });
            };
            Promise.resolve().then(() => run(url)).then(value => {
                record(true);
                if (done) return;
                pending--;
                if (preferred(value)) return finish(value);
                fallback = betterFallback(fallback, value);
                if (next < ordered.length) launch();
                else if (!pending) finish(fallback);
            }, () => {
                record(false);
                if (done) return;
                pending--;
                if (next < ordered.length) launch();
                else if (!pending) finish(fallback, fallback ? null : new Error('all upstreams failed'));
            });
            if (next < ordered.length) timer = setTimeout(launch, 100);
        }
        if (!ordered.length) finish(null, new Error('no upstreams'));
        else launch();
    });
}

function preferredDnsAnswer(data, type, preferEch) {
    return data.Status === 0 && data.Answer?.some(a =>
        a.type === type && (!preferEch || parseHttpsRecord(a.data)?.ech));
}

/**
 * 获取 Cloudflare ECH 公钥（带内存缓存）
 */
// Meta does not consistently publish ECH in DNS. Prefer per-origin DNS data;
// the existing legacy configuration remains a short-lived compatibility fallback.
async function fetchMetaEch(domain, clientIP) {
    domain = domain.toLowerCase().replace(/\.$/, '');
    const key = `meta-legacy-v1:${domain}:${encodeURIComponent(ecsPrefix(clientIP) || 'none')}`;
    const cached = cacheMap.get(key);
    if (cached && cached.expire > Date.now()) {
        return { ech: META_ECH_CONFIG, ttl: Math.max(0, Math.floor((cached.expire - Date.now()) / 1000)), legacy: true };
    }
    const info = await fetchRealEch(domain, clientIP);
    if (info) return info;
    // Preserve the original compatibility behavior only for named Meta services.
    // An IP ownership probe is not evidence that a third-party origin accepts this key.
    if (!META_DOMAINS.some(d => domain === d || domain.endsWith('.' + d))) return null;
    // Recheck shortly; do not send three upstream requests for every Meta HTTPS lookup.
    rememberCacheEntry(key, { expire: Date.now() + 30_000 });
    return { ech: META_ECH_CONFIG, ttl: 30, legacy: true };
}

async function fetchRealEch(echDomain, clientIP) {
    echDomain = echDomain.toLowerCase().replace(/\.$/, '');
    // Cloudflare's public bootstrap is shared; custom ECH names may vary by ECS.
    const lookupIP = echDomain === 'cloudflare-ech.com' ? '' : clientIP;
    const cacheKey = `ech-v3:${encodeURIComponent(echDomain)}:${encodeURIComponent(ecsPrefix(lookupIP) || 'none')}`;
    const cacheUrl = `https://dns-cache/${cacheKey}`;
    // 1. 内存缓存
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return { ech: cached.value, ttl: Math.max(0, Math.floor((cached.expire - Date.now()) / 1000)) };
    // 2. Cache API（新增）
    try {
        const cachedText = await readCache(cacheUrl);
        if (cachedText) {
            const data = JSON.parse(cachedText);
            if (data?.ech && data.expire > Date.now()) {
                rememberCacheEntry(cacheKey, { value: data.ech, expire: data.expire });
                return { ech: data.ech, ttl: Math.max(0, Math.floor((data.expire - Date.now()) / 1000)) };
            }
        }
    } catch (e) {}
    // 3. 上游查询（多上游校验式竞速：优先取含 ECH 的 HTTPS 记录，
    //    不再单点依赖 dns.google；RFC3597 格式已由 parseSvcParamsFromData 兼容）
    try {
        let data = await queryUpstreamDNS(echDomain, 65, lookupIP, null, true);
        if (!data) {
            await new Promise(r => setTimeout(r, 100));
            data = await queryUpstreamDNS(echDomain, 65, lookupIP, null, true);
        }
        if (data && data.Answer) {
            const rec = data.Answer.find(r => r.type === 65 && parseHttpsRecord(r.data)?.ech);
            if (rec) {
                const parsed = parseHttpsRecord(rec.data);
                if (parsed && parsed.ech) {
                    const ttl = upstreamAnswerTtl(data, ECH_CACHE_TTL / 1000);
                    if (ttl > 0) {
                        const expire = Date.now() + ttl * 1000;
                        rememberCacheEntry(cacheKey, { value: parsed.ech, expire });
                        writeCache(cacheUrl, JSON.stringify({ ech: parsed.ech, expire }), ttl);
                    }
                    return { ech: parsed.ech, ttl };
                }
            }
        }
    } catch {}
    return null;
}

/**
 * 通用 HTTPS 记录解析（支持两种格式）：
 * 1. 可读格式："1 . alpn=h3,h2 ech=xxx ipv4hint=1.2.3.4"
 * 2. RFC3597 格式："\# 136 00 01 00 00 ..."（部分上游如 Quad9/Cloudflare 返回）
 * 返回参数数组 [{key, val}, ...]
 */
function parseSvcParamsFromData(dataStr) {
    const parts = dataStr.split(/\s+/);
    if (parts.length < 3) return [];
    // RFC3597 十六进制格式
    if (parts[0] === '\\#' || parts[0] === '#') {
        try {
            const hex = parts.slice(2).join('');
            const bytes = new Uint8Array(Math.floor(hex.length / 2));
            for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            if (bytes.length < 3) return [];
            const dv = new DataView(bytes.buffer);
            let off = 2;
            // 跳过 TargetName（0=根，或标签序列）
            while (off < bytes.length) {
                const len = bytes[off];
                if (len === 0) { off++; break; }
                if (len > 63) break;
                off += 1 + len;
            }
            const params = [];
            while (off + 4 <= bytes.length) {
                const key = dv.getUint16(off);
                const len = dv.getUint16(off + 2);
                off += 4;
                if (off + len > bytes.length) break;
                const valBytes = bytes.slice(off, off + len);
                off += len;
                const keyName = Object.keys(SVC_PARAM_IDS).find(k => SVC_PARAM_IDS[k] === key) || ('key' + key);
                let val;
                if (keyName === 'alpn') {
                    const ids = [];
                    let o = 0;
                    while (o < valBytes.length) {
                        const l = valBytes[o];
                        ids.push(new TextDecoder().decode(valBytes.slice(o + 1, o + 1 + l)));
                        o += 1 + l;
                    }
                    val = ids.join(',');
                } else if (keyName === 'ipv4hint') {
                    const ips = [];
                    for (let i = 0; i + 4 <= valBytes.length; i += 4) ips.push(Array.from(valBytes.slice(i, i + 4)).join('.'));
                    val = ips.join(',');
                } else if (keyName === 'ipv6hint') {
                    const ips = [];
                    for (let i = 0; i + 16 <= valBytes.length; i += 16) ips.push(formatIPv6(valBytes.slice(i, i + 16)));
                    val = ips.join(',');
                } else {
                    // ech 等二进制字段 → base64url（Workers 环境无 Buffer，用 btoa）
                    let bin = '';
                    for (let i = 0; i < valBytes.length; i++) bin += String.fromCharCode(valBytes[i]);
                    val = btoa(bin).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
                }
                params.push({ key: keyName, val });
            }
            return params;
        } catch (e) {
            return [];
        }
    }
    // 可读格式
    const params = [];
    for (let i = 2; i < parts.length; i++) {
        const eqIdx = parts[i].indexOf('=');
        if (eqIdx === -1) continue;
        params.push({ key: parts[i].substring(0, eqIdx), val: parts[i].substring(eqIdx + 1) });
    }
    return params;
}

/**
 * 简单解析 HTTPS 记录，提取 ech/alpn 字段
 */
function parseHttpsRecord(dataStr) {
    const params = parseSvcParamsFromData(dataStr);
    const result = {};
    for (const p of params) {
        if (p.key === 'ech') result.ech = p.val;
        else if (p.key === 'alpn') result.alpn = p.val;
    }
    return Object.keys(result).length ? result : null;
}

/**
 * 打包 HTTPS 记录（包含 hints）
 */
function packHttpsParamsWithHints(priority, target, params, ipv4Hints, ipv6Hints) {
    if (ipv4Hints && ipv4Hints.length > 0) {
        const unique = [...new Set(ipv4Hints)].slice(0, MAX_FINAL);
        if (unique.length > 0) params.push({ key: 'ipv4hint', val: unique.join(',') });
    }
    if (ipv6Hints && ipv6Hints.length > 0) {
        const unique = [...new Set(ipv6Hints)].slice(0, MAX_FINAL);
        if (unique.length > 0) params.push({ key: 'ipv6hint', val: unique.join(',') });
    }
    return packHttpsParams(priority, target, params);
}

/**
 * 打包 HTTPS 记录（内部使用）
 */
function packHttpsParams(priority, target, params) {
    const targetBuf = target === "." ? new Uint8Array([0]) : encodeDnsName(target);
    const paramBufs = params.map(p => encodeSvcParam(p.key, p.val)).filter(b => b);
    paramBufs.sort((a, b) => new DataView(a.buffer).getUint16(0) - new DataView(b.buffer).getUint16(0));
    let totalLen = 2 + targetBuf.length;
    for (const b of paramBufs) totalLen += b.length;
    const res = new Uint8Array(totalLen);
    const v = new DataView(res.buffer);
    v.setUint16(0, priority);
    res.set(targetBuf, 2);
    let offset = 2 + targetBuf.length;
    for (const b of paramBufs) { res.set(b, offset); offset += b.length; }
    return res;
}

/**
 * 编码 SVCB 参数
 */
function encodeSvcParam(key, value) {
    const id = SVC_PARAM_IDS[key];
    if (id === undefined) return null;
    let valBuf;

    // mandatory：排序、去重、安全处理
    if (key === 'mandatory') {
        const keys = [...new Set(
            value.split(',')
                .map(s => s.trim())
                .filter(Boolean)
                .map(k => SVC_PARAM_IDS[k])
                .filter(v => v !== undefined)
        )].sort((a, b) => a - b);

        if (keys.length === 0) return null;
        valBuf = new Uint8Array(keys.length * 2);
        const dv = new DataView(valBuf.buffer);
        keys.forEach((id, i) => dv.setUint16(i * 2, id));
    }
    // no-default-alpn：空值
    else if (key === 'no-default-alpn') {
        valBuf = new Uint8Array(0);
    }
    // alpn：字符串列表编码，增加长度限制
    else if (key === 'alpn') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        for (const p of parts) {
            if (p.length > 255) return null; // 标识长度不得超过 255 字节
        }
        valBuf = new Uint8Array(parts.reduce((a, b) => a + b.length + 1, 0));
        let o = 0;
        for (const p of parts) {
            valBuf[o++] = p.length;
            for (let i = 0; i < p.length; i++) valBuf[o++] = p.charCodeAt(i);
        }
    }
    // port：严格校验
    else if (key === 'port') {
        const portNum = Number(value);
        if (!Number.isInteger(portNum) || portNum < 0 || portNum > 65535) return null;
        valBuf = new Uint8Array(2);
        new DataView(valBuf.buffer).setUint16(0, portNum);
    }
    // ipv4hint
    else if (key === 'ipv4hint') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        valBuf = new Uint8Array(parts.length * 4);
        let offset = 0;
        for (const ip of parts) {
            const bytes = ipToBytes(ip);
            if (!bytes) return null;
            valBuf.set(bytes, offset);
            offset += 4;
        }
    }
    // ipv6hint
    else if (key === 'ipv6hint') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        valBuf = new Uint8Array(parts.length * 16);
        let offset = 0;
        for (const ip of parts) {
            const bytes = ipv6ToBytes(ip);
            if (!bytes) return null;
            valBuf.set(bytes, offset);
            offset += 16;
        }
    }
    // ech 等 Base64URL 字段，增加填充处理
    else {
        try {
            let b64 = value.replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';   // 补齐 padding
            const s = atob(b64);
            valBuf = new Uint8Array(s.length);
            for (let i = 0; i < s.length; i++) valBuf[i] = s.charCodeAt(i);
        } catch (e) {
            console.error('encodeSvcParam base64 error:', e);
            return null;
        }
    }

    const res = new Uint8Array(4 + valBuf.length);
    const dv = new DataView(res.buffer);
    dv.setUint16(0, id);
    dv.setUint16(2, valBuf.length);
    res.set(valBuf, 4);
    return res;
}
/**
 * 域名编码为 DNS 标签格式
 */
function encodeDnsName(domain) {
    const parts = domain.split('.');
    const buf = new Uint8Array(domain.length + 2);
    let offset = 0;
    for (const part of parts) {
        buf[offset++] = part.length;
        for (let i = 0; i < part.length; i++) buf[offset++] = part.charCodeAt(i);
    }
    buf[offset++] = 0;
    return buf.slice(0, offset);
}

/**
 * 解析 DNS 报文头部与问题域
 */
function parseDnsPacket(buf) {
    const v = new DataView(buf);
    if (buf.byteLength < 12) return null;
    let offset = 12;
    const labels = [];
    let questionCompressed = false;
    while (offset < buf.byteLength) {
        const len = v.getUint8(offset);
        if (len === 0) { offset++; break; }
        if ((len & 0xC0) === 0xC0) { questionCompressed = true; offset += 2; break; }
        offset++;
        labels.push(new TextDecoder().decode(buf.slice(offset, offset + len)));
        offset += len;
    }
    if (offset + 4 > buf.byteLength) return null;
    const qType = v.getUint16(offset);
    const qclass = v.getUint16(offset + 2);
    offset += 4;
    const questionEnd = offset;
    // 探测附加区是否携带 EDNS0 OPT（用于决定响应是否回显 OPT，RFC6891）
    let hasEdns = false;
    let dnssecOk = false;
    const arCount = v.getUint16(10);
    for (let i = 0; i < arCount && offset < buf.byteLength; i++) {
        while (offset < buf.byteLength) {
            const l = v.getUint8(offset);
            if (l === 0) { offset += 1; break; }
            if ((l & 0xC0) === 0xC0) { offset += 2; break; }
            offset += 1 + l;
        }
        if (offset + 10 > buf.byteLength) break;
        const rtype = v.getUint16(offset);
        const rdlen = v.getUint16(offset + 8);
        if (rtype === 41) {
            hasEdns = true;
            dnssecOk = (v.getUint16(offset + 6) & 0x8000) !== 0;
        }
        offset += 10 + rdlen;
        if (rtype === 41) break;
    }
    return {
        id: v.getUint16(0),
        hasEdns,
        dnssecOk,
        questionCompressed,
        questionEnd,
        questions: [{ name: labels.join('.'), type: qType, qclass }]
    };
}

/**
 * 构造多答案 DNS 响应报文
 */
function createMultiAnsResponse(id, qn, qt, rds, ttl = 3600, echoEdns = false, rcode = 0) {
    const encodedName = encodeDnsName(qn);
    const questionLen = 12 + encodedName.length + 4;
    const pointer = 0xC000 | 12;
    // 客户端带 EDNS0 时回显一条空 OPT（owner=root,type=41,class=1232,ttl=0,rdlen=0），共 11 字节。
    // 不做 DNSSEC，因此 DO 位保持 0，不虚报 AD。
    const OPT_LEN = echoEdns ? 11 : 0;
    let totalLen = questionLen + OPT_LEN;
    for (const r of rds) totalLen += 2 + 2 + 2 + 4 + 2 + r.length;
    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);
    v.setUint16(0, id);
    v.setUint16(2, 0x8180 | (rcode & 0x0F));   // QR=1,RD=1,RA=1 + RCODE
    v.setUint16(4, 1);
    v.setUint16(6, rds.length);
    v.setUint16(8, 0);
    v.setUint16(10, echoEdns ? 1 : 0);
    let offset = 12;
    buf.set(encodedName, offset); offset += encodedName.length;
    v.setUint16(offset, qt); offset += 2;
    v.setUint16(offset, 1);  offset += 2;
    for (const r of rds) {
        v.setUint16(offset, pointer); offset += 2;
        v.setUint16(offset, qt); offset += 2;
        v.setUint16(offset, 1); offset += 2;
        v.setUint32(offset, ttl); offset += 4;
        v.setUint16(offset, r.length); offset += 2;
        buf.set(r, offset); offset += r.length;
    }
    if (echoEdns) {
        v.setUint8(offset, 0); offset += 1;        // root name
        v.setUint16(offset, 41); offset += 2;      // TYPE=OPT
        v.setUint16(offset, 1232); offset += 2;    // CLASS=UDP payload size
        v.setUint32(offset, 0); offset += 4;       // ext-rcode/version/flags(DO=0)
        v.setUint16(offset, 0); offset += 2;       // RDLEN=0
    }
    return buf.buffer;
}

/**
 * 转发二进制 DNS 查询（多上游竞速，带超时）
 */
// Validate section boundaries and compression before trusting upstream wire data.
// RDATA remains opaque so unknown record types can still be forwarded unchanged.
function inspectDnsWire(buffer) {
    try {
        const bytes = new Uint8Array(buffer);
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (bytes.length < 12 || bytes.length > 65535) return null;
        function readName(start) {
            let cursor = start, end = null, length = 1, compressed = false;
            const labels = [], visited = new Set();
            while (true) {
                if (cursor >= bytes.length || visited.has(cursor)) throw new Error('invalid DNS name');
                visited.add(cursor);
                const size = bytes[cursor];
                if ((size & 0xc0) === 0xc0) {
                    if (cursor + 1 >= bytes.length) throw new Error('truncated DNS pointer');
                    if (end === null) end = cursor + 2;
                    compressed = true;
                    cursor = ((size & 0x3f) << 8) | bytes[cursor + 1];
                    continue;
                }
                if (size & 0xc0) throw new Error('invalid DNS label');
                cursor++;
                if (size === 0) return { end: end ?? cursor, key: JSON.stringify(labels), compressed };
                length += size + 1;
                if (length > 255 || cursor + size > bytes.length) throw new Error('truncated DNS label');
                labels.push(String.fromCharCode(...bytes.subarray(cursor, cursor + size))
                    .replace(/[A-Z]/g, c => c.toLowerCase()));
                cursor += size;
            }
        }
        let offset = 12;
        const questions = [];
        for (let i = 0; i < view.getUint16(4); i++) {
            const name = readName(offset);
            offset = name.end;
            if (offset + 4 > bytes.length) return null;
            questions.push({ key: name.key, compressed: name.compressed,
                type: view.getUint16(offset), qclass: view.getUint16(offset + 2) });
            offset += 4;
        }
        const questionEnd = offset;
        const recordCount = view.getUint16(6) + view.getUint16(8) + view.getUint16(10);
        for (let i = 0; i < recordCount; i++) {
            offset = readName(offset).end;
            if (offset + 10 > bytes.length) return null;
            const rdlength = view.getUint16(offset + 8);
            offset += 10 + rdlength;
            if (offset > bytes.length) return null;
        }
        if (offset !== bytes.length) return null;
        return { id: view.getUint16(0), flags: view.getUint16(2), questions, questionEnd };
    } catch {
        return null;
    }
}

async function forwardQuery(body, upstreams = UPSTREAM_DNS_LIST) {
    const reqInit = {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body
    };
    const query = new Uint8Array(body);
    const queryId = query.byteLength >= 2 ? new DataView(query.buffer, query.byteOffset, query.byteLength).getUint16(0) : 0;
    const parsedQuery = inspectDnsWire(body);
    // Race valid complete DNS replies, not just the first HTTP-200 header.
    // A temporary DNS SERVFAIL is not a successful upstream resolution.
    const requestUpstream = url =>
        fetchWithTimeout(url, reqInit, 2000, async res => {
            if (!res.ok || !(res.headers.get('Content-Type') || '').toLowerCase().startsWith('application/dns-message')) {
                throw new Error('upstream returned non-DNS response');
            }
            const packet = await res.arrayBuffer();
            if (packet.byteLength < 12 || packet.byteLength > 65535) throw new Error('bad DNS packet length');
            const reply = inspectDnsWire(packet);
            if (!parsedQuery || !reply || reply.id !== queryId || !(reply.flags & 0x8000) ||
                (reply.flags & 0x7800) !== (parsedQuery.flags & 0x7800) ||
                [2, 5].includes(reply.flags & 0x0f) ||
                reply.questions.length !== parsedQuery.questions.length ||
                reply.questions.some((question, i) => question.key !== parsedQuery.questions[i].key ||
                    question.type !== parsedQuery.questions[i].type ||
                    question.qclass !== parsedQuery.questions[i].qclass)) {
                throw new Error('invalid DNS reply or SERVFAIL');
            }
            return new Response(packet, {
                headers: { 'Content-Type': 'application/dns-message' }
            });
        });
    try {
        return await raceUpstreams(upstreams, 'wire', requestUpstream, () => true);
    } catch {
        // Do not turn a 503 HTML page into HTTP 200 application/dns-message.
        // Return a valid SERVFAIL packet with the original uncompressed question.
        const preserveQuestion = parsedQuery && parsedQuery.questions.length === 1 &&
            !parsedQuery.questions[0].compressed;
        const output = preserveQuestion ? query.slice(0, parsedQuery.questionEnd) : new Uint8Array(12);
        if (!preserveQuestion) output.set(query.subarray(0, Math.min(2, query.byteLength)), 0);
        const view = new DataView(output.buffer);
        const requestedRd = query.byteLength > 3 && (query[2] & 1) ? 0x0100 : 0;
        view.setUint16(2, 0x8082 | requestedRd);
        view.setUint16(4, preserveQuestion ? 1 : 0);
        view.setUint16(6, 0); view.setUint16(8, 0); view.setUint16(10, 0);
        return new Response(output.buffer, {
            headers: { 'Content-Type': 'application/dns-message' }
        });
    }
}

/**
 * 追加一条空 EDNS0 OPT（RFC6891）。
 * 缓存体一律以"不含 OPT"的规范形式存储，响应时再按本次请求是否携带 EDNS 决定是否追加，
 * 否则先到的 EDNS 客户端会让缓存把 OPT 带给从未请求它的客户端（且反向也会丢 OPT）。
 */
function appendOpt(buffer) {
    const src = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    if (src.byteLength < 12) return buffer;
    const out = new Uint8Array(src.byteLength + 11);
    out.set(src, 0);
    let o = src.byteLength;
    out[o++] = 0;                          // root name
    out[o++] = 0; out[o++] = 41;           // TYPE = OPT
    out[o++] = 0x04; out[o++] = 0xd0;      // CLASS = 1232 (UDP payload size)
    out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0; // ext-rcode / version / flags(DO=0)
    out[o++] = 0; out[o++] = 0;            // RDLEN = 0
    const dv = new DataView(out.buffer);
    dv.setUint16(10, dv.getUint16(10) + 1); // ARCOUNT++
    return out;
}

/**
 * 回写事务 ID。
 * RFC 8484/RFC 1035 要求响应的事务 ID 与查询一致；缓存体是"首次请求"的字节，
 * 直接复用会让后续客户端收到不匹配的 ID 而被判为无效响应（AdGuard Home/dnsproxy 等会丢弃）。
 * 返回副本，绝不就地修改缓存体。
 */
function withDnsId(buffer, id) {
    if (id === undefined || id === null) return buffer;
    const src = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    if (src.byteLength < 12) return buffer;
    const out = src.slice();
    out[0] = (id >>> 8) & 0xff;
    out[1] = id & 0xff;
    return out;
}

/**
 * 返回二进制 DNS 响应
 */
function dnsResponse(buffer, extraHeaders = null) {
    const headers = {
        'Content-Type': 'application/dns-message',
        'Access-Control-Allow-Origin': '*',
        // Do not let generic HTTP caches reuse personalized queries or override DNS TTLs.
        'Cache-Control': 'no-store'
    };
    if (extraHeaders) Object.assign(headers, extraHeaders);
    return new Response(buffer, { headers });
}
/**
 * 兜底记录解析：直接查询上游并返回原始答案。
 * 适用于所有非 A/AAAA/HTTPS 类型，也可用于 HTTPS 类型的通用解析。
 */
async function resolveFallbackRecord(domain, type, clientIP, upstreamUrl = null) {
    const typeMap = {
        'A': 1,
        'AAAA': 28,
        'CNAME': 5,
        'TXT': 16,
        'MX': 15,
        'NS': 2,
        'HTTPS': 65
    };
    const dnsType = typeMap[type] || 1;

    const data = await queryUpstreamDNS(domain, dnsType, clientIP, upstreamUrl);
    if (!data) return { domain, type, answers: [], ech: null, rcode: 2, ttl: 0 };

    if (type === 'HTTPS') {
        const result = { domain, type, answers: [], rcode: data.Status === 3 ? 3 : 0, ttl: upstreamAnswerTtl(data, 600) };
        if (data?.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecordFull(rec.data);
                if (parsed) {
                    result.ech = parsed.ech || null;
                    result.ipv4hints = parsed.ipv4hints || [];
                    result.ipv6hints = parsed.ipv6hints || [];
                    result.alpn = parsed.alpn || '';
                    if (parsed.ech) result.echSource = 'dns';
                }
            }
        }
        return result;
    }

    const answers = data?.Answer?.filter(r => r.type === dnsType).map(r => r.data) || [];
    return { domain, type, answers, ech: null, rcode: data.Status === 3 ? 3 : 0, ttl: upstreamAnswerTtl(data) };
}
/**
 * 加载/更新国内域名集合
 * 第一次调用时立即用内置后缀构建集合，后续异步拉取远程列表，不阻塞请求。
 */
async function ensureCNDomainSet() {
    const now = Date.now();
    if (!cnDomainSet) cnDomainSet = new Set(CN_DOMAIN_SUFFIXES);
    if (cnRefreshRunning || now < cnRetryAt || now - cnDomainLastFetch < CN_DOMAIN_CACHE_TTL) return;
    cnRefreshRunning = true;
    const cacheKey = 'https://dns-cache/cn/domains-v2';
    try {
        const cachedText = await readCache(cacheKey);
        let data = cachedText ? JSON.parse(cachedText) : null;
        if (!data?.text || !(data.expire > Date.now())) {
            const text = await fetchWithTimeout(CN_DOMAIN_LIST_URL, {}, 5000, res => {
                if (!res.ok) throw new Error('CN list HTTP error');
                return res.text();
            });
            if (!text.trim()) throw new Error('empty CN list');
            data = { text, expire: Date.now() + CN_DOMAIN_CACHE_TTL };
            await writeCache(cacheKey, JSON.stringify(data), CN_DOMAIN_CACHE_TTL / 1000);
        }
        const domains = new Set(CN_DOMAIN_SUFFIXES);
        for (const line of data.text.split(/\r?\n/)) {
            const d = line.trim().toLowerCase();
            if (d && !d.startsWith('#')) domains.add(d);
        }
        cnDomainSet = domains;
        cnDomainLastFetch = data.expire - CN_DOMAIN_CACHE_TTL;
        cnRetryAt = 0;
    } catch {
        // Keep the last usable data; retry soon instead of treating failure as a 7-day success.
        cnRetryAt = Date.now() + 60_000;
    } finally { cnRefreshRunning = false; }
}

/**
 * 判断是否为国内域名
 * 匹配规则：完整域名在集合中，或域名以集合中某个 '.' 开头的后缀结尾。
 */
function isCNDomain(domain) {
    // cnDomainSet 理论上已被 ensureCNDomainSet 同步初始化，此处兜底防御
    if (!cnDomainSet) return false;
    // 远端 direct-list.txt 是纯域名列表（不含前导点）。必须逐级剥离标签匹配后缀，
    // 否则 www.taobao.com 这类子域名永不判为国内域名，分流形同虚设。
    // 逐级查询同时把每次查询的 O(n) 全量扫描降为 O(标签数) 次哈希查找。
    for (let d = domain; ; ) {
        if (cnDomainSet.has(d) || cnDomainSet.has('.' + d)) return true;
        const i = d.indexOf('.');
        if (i === -1) return false;
        d = d.slice(i + 1);
    }
}

/**
 * 从 IPv4 CIDR 生成随机可用地址（排除网络号与广播地址）
 * @param {string} prefixStr - 如 "1.2.3.0/24"
 * @returns {string[]} 随机 IPv4 地址数组
 */
function generateRandomIPv4(prefixStr) {
    const [addr, bitsStr] = prefixStr.split('/');
    const bits = bitsStr === undefined ? 32 : parseInt(bitsStr, 10);
    if (!ipToBytes(addr)) return [];          // 非法 IPv4 直接放弃
    const base = ipToLong(addr);
    if (isNaN(bits) || bits < 0 || bits > 32) return [];
    const size = 2 ** (32 - bits);
    if (size <= 2) return [];
    const hostBits = 32 - bits;
    const mask = hostBits >= 32 ? 0 : ((1 << hostBits) - 1) >>> 0;
    const net = (base & ~mask) >>> 0;
    const out = [];
    for (let i = 0; i < RANDOM_IPV6_COUNT; i++) {
        const n = (net + 1 + Math.floor(Math.random() * (size - 2))) >>> 0;
        out.push(bytesToIp(new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])));
    }
    return out;
}

/**
 * 从 IPv6 前缀生成指定数量的随机 IPv6 地址
 * @param {string} prefixStr - 前缀字符串，如 "2001:4860:4827:7700::/64"
 * @returns {string[]} 随机 IPv6 地址数组
 */
function generateRandomIPv6(prefixStr) {
    const [addrStr, bitsStr] = prefixStr.split('/');
    const prefixLen = parseInt(bitsStr, 10);
    if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 128) return [];

    // 将前缀地址转换为 128 位 BigInt
    const baseIP = ipv6ToBigInt(addrStr);
    const hostBits = 128 - prefixLen;
    const maxHost = (1n << BigInt(hostBits)) - 1n;

    // 主机位不能全0（网络地址）和全1（广播地址），实际 Google 全段可用，这里保守过滤
    const minHost = 1n;
    const maxValidHost = maxHost - 1n;

    const ips = [];
    for (let i = 0; i < RANDOM_IPV6_COUNT; i++) {
        const randomHost = randomBigInt(minHost, maxValidHost);
        const fullIP = baseIP | randomHost;
        ips.push(bigIntToIPv6(fullIP));
    }
    return ips;
}

/**
 * 生成介于 min 和 max 之间的随机 BigInt（包含两端）
 */
function randomBigInt(min, max) {
    const range = max - min + 1n;
    const bits = range.toString(2).length;
    let rand;
    const maxAttempts = 10; // 防止无限循环
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        rand = 0n;
        for (let i = 0; i < 16; i++) {
            rand = (rand << 8n) | BigInt(bytes[i]);
        }
        const mask = (1n << BigInt(bits)) - 1n;
        rand = rand & mask;
        if (rand <= range) {
            return min + rand;
        }
    }
    // 回退：返回 min
    return min;
}

/**
 * BigInt 转压缩 IPv6 字符串
 * 遵循 RFC 5952 标准，精准压缩全零段，规避边缘正则导致的格式隐患
 */
function bigIntToIPv6(big) {
    const segments = [];
    for (let i = 0; i < 8; i++) {
        // 每次向右平移 16 位，并取出最后的 16 位，转换为 16 进制字符串
        segments.unshift(Number((big >> BigInt(i * 16)) & 0xFFFFn).toString(16));
    }
    // 寻找最长的连续全零段（RFC 5952 标准压缩逻辑）
    let maxStart = -1, maxLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
        if (segments[i] === '0') {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > maxLen) {
                maxLen = curLen;
                maxStart = curStart;
            }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }
    // 只有全零段长度大于 1 时才进行 "::" 压缩
    if (maxLen > 1) {
        const head = segments.slice(0, maxStart).join(':');
        const tail = segments.slice(maxStart + maxLen).join(':');
        return `${head}::${tail}`;
    }    
    // 如果没有连续的零段，则直接用单冒号连接返回
    return segments.join(':');
}

/**
 * 获取前缀对应的随机 IP 列表（带缓存）
 */
function getPrefixIPs(prefixStr) {
    const cached = prefixCache.get(prefixStr);
    if (cached && Date.now() < cached.expire) {
        return cached.ips;
    }
    // IPv4 CIDR：generateRandomIPv6 会把 "1.2.3.0" 按十六进制解析成 1n，
    // 再当 IPv6 前缀随机出不可达地址，必须单独处理。
    const ips = prefixStr.includes(':') ? generateRandomIPv6(prefixStr) : generateRandomIPv4(prefixStr);
    prefixCache.set(prefixStr, { ips, expire: Date.now() + PREFIX_CACHE_TTL });
    return ips;
}

// ===================== IP 转换 =====================
function extractIpsFromPacket(buffer) {
    const ips = [];
    const view = new DataView(buffer);
    if (buffer.byteLength < 12) return [];
    const ancount = view.getUint16(6);
    const totalRecords = ancount + view.getUint16(8) + view.getUint16(10);
    let offset = 12;
    try {
        for (let i = 0; i < view.getUint16(4); i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 5;
        }
        for (let i = 0; i < totalRecords; i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 1;
            const type = view.getUint16(offset); offset += 8;
            const rdlen = view.getUint16(offset); offset += 2;
            if (type === 1 && rdlen === 4) {
                ips.push(Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.'));
            } else if (type === 28 && rdlen === 16) {
                const raw = new Uint8Array(buffer.slice(offset, offset + 16));
                ips.push(formatIPv6(raw));
            }
            offset += rdlen;
        }
    } catch (e) {}
    return ips;
}

function formatIPv6(bytes) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
        parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    let longestStart = -1, longestLen = 0;
    let currentStart = -1, currentLen = 0;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '0') {
            if (currentStart === -1) currentStart = i;
            currentLen++;
            if (currentLen > longestLen) { longestLen = currentLen; longestStart = currentStart; }
        } else {
            currentStart = -1; currentLen = 0;
        }
    }
    if (longestLen > 1) {
        parts.splice(longestStart, longestLen, '');
        if (longestStart === 0) parts.unshift('');
        if (longestStart + longestLen === 8) parts.push('');
    }
    return parts.join(':').replace(/:{3,}/, '::');
}

function formatIPv6FromBytes(bytes) { return formatIPv6(bytes); }

function ipToLong(ip) {
    return ip.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
}

function ipv6ToBigInt(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        const [f, s] = ip.split('::');
        const fP = f ? f.split(':') : [];
        const sP = s ? s.split(':') : [];
        p = [...fP, ...Array(8 - fP.length - sP.length).fill('0'), ...sP];
    }
    return p.reduce((a, b) => (a << 16n) + BigInt(parseInt(b || '0', 16)), 0n);
}

// 返回 4 字节；非法输入返回 null（调用方需过滤），避免静默产出 rdlength 错误的畸形 rdata
function ipToBytes(ip) {
    const p = String(ip).split('.');
    if (p.length !== 4) return null;
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        const n = Number(p[i]);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        b[i] = n;
    }
    return b;
}

function ipv6ToBytes(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        if (ip.split('::').length !== 2) return null;
        const [l, r] = ip.split('::');
        const lp = l ? l.split(':') : [];
        const rp = r ? r.split(':') : [];
        if (lp.length + rp.length >= 8 || [...lp, ...rp].some(v => !v)) return null;
        p = [...lp, ...Array(8 - lp.length - rp.length).fill('0'), ...rp];
    }
    if (p.length !== 8) return null;
    for (const v of p) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(v)) return null;
    }
    const b = new Uint8Array(16);
    p.forEach((v, i) => {
        const val = parseInt(v, 16) || 0;
        b[i * 2] = val >> 8;
        b[i * 2 + 1] = val & 0xFF;
    });
    return b;
}

function bytesToIp(bytes) { return Array.from(bytes).join('.'); }
function bytesToIp6(bytes) { return formatIPv6(bytes); }

// ===================== CIDR 编译与匹配 =====================
function compileCidrs(cidrList) {
    const v4 = [], v6 = [];
    for (const cidr of cidrList) {
        try {
            const [ip, bitsStr] = cidr.split('/');
            const bits = parseInt(bitsStr, 10);
            if (ip.includes(':')) {
                const mask = ~( (1n << (128n - BigInt(bits))) - 1n );
                const ipBn = ipv6ToBigInt(ip);
                v6.push({ start: ipBn & mask, end: (ipBn & mask) | ( (1n << (128n - BigInt(bits))) - 1n ) });
            } else {
                const mask = ~((1 << (32 - bits)) - 1);
                const ipNum = ipToLong(ip);
                v4.push({ start: (ipNum & mask) >>> 0, end: ((ipNum & mask) | ((1 << (32 - bits)) - 1)) >>> 0 });
            }
        } catch (e) {}
    }
    return { v4, v6 };
}

function isIpInCidrs(ip, compiled) {
    if (ip.includes(':')) {
        try {
            const ipBn = ipv6ToBigInt(ip);
            return compiled.v6.some(r => ipBn >= r.start && ipBn <= r.end);
        } catch {}
    } else {
        try {
            const ipNum = ipToLong(ip);
            return compiled.v4.some(r => ipNum >= r.start && ipNum <= r.end);
        } catch {}
    }
    return false;
}

// ===================== 归属探测 =====================
async function activeProbeOwner(domain, ctx, clientIP) {
    const cacheKey = `owner-v2:${domain}:${encodeURIComponent(ecsPrefix(clientIP) || 'none')}`;
    const cacheUrl = `https://dns-cache/${cacheKey}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;
    try {
        const text = await readCache(cacheUrl);
        if (text) {
            const entry = JSON.parse(text);
            if (entry.expire > Date.now()) {
                rememberCacheEntry(cacheKey, entry);
                return entry.value;
            }
        }
    } catch {}
    const data = await queryUpstreamDNS(domain, 1, clientIP);
    if (!data) return null; // transient outage must not become a negative ownership cache
    const ips = (data.Answer || []).filter(r => r.type === 1 && ipToBytes(r.data)).map(r => r.data);
    const owners = ips.map(ip => isIpInCidrs(ip, getCompiledMeta()) ? 'META' : isIpInCidrs(ip, getCompiledCF()) ? 'CF' : null);
    // Mixed CDN/origin answers are not proof of a single CDN owner.
    const owner = owners.length && owners[0] && owners.every(x => x === owners[0]) ? owners[0] : null;
    const value = owner ? { owner, ips } : null;
    const ttl = upstreamAnswerTtl(data, owner ? 300 : 60);
    if (ttl > 0) {
        const entry = { value, expire: Date.now() + ttl * 1000 };
        rememberCacheEntry(cacheKey, entry);
        await writeCache(cacheUrl, JSON.stringify(entry), ttl);
    }
    return value;
}

// ===================== 订阅处理 =====================
// External fetch targets require an explicit exact-host allowlist from the operator.
// Arbitrary URLs supplied by a caller must never be fetched by a public Worker.
function safeSubscriptionUrl(raw, env) {
    const allowed = String(env?.DOH_ALLOWED_SUB_HOSTS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (!allowed.length) return null;
    try {
        const url = new URL(raw);
        if (url.protocol !== 'https:' || url.port && url.port !== '443' ||
            url.username || url.password || !allowed.includes(url.hostname.toLowerCase())) return null;
        return url.toString();
    } catch {
        return null;
    }
}

async function limitedResponseText(response, maxBytes) {
    const claimed = Number(response.headers.get('Content-Length') || 0);
    if (!response.ok || claimed > maxBytes) throw new Error('subscription too large');
    if (!response.body) return '';
    const reader = response.body.getReader();
    const parts = [];
    let size = 0;
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxBytes) {
                await reader.cancel();
                throw new Error('subscription too large');
            }
            parts.push(value);
        }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size);
    let pos = 0;
    for (const p of parts) { bytes.set(p, pos); pos += p.byteLength; }
    return new TextDecoder().decode(bytes);
}

async function applySubConfig(config, env) {
    const sub = config.sub;
    if (!sub) return;
    const excludeItems = new Set(
        (config.exclude || '').split(',').map(s => s.trim()).filter(s => s)
    );
    const areaFilter = (config.area || '').trim().toLowerCase();
    const areaMap = {
        'hk': '香港','hkg': '香港','sg': '新加坡','sin': '新加坡',
        'jp': '日本','tyo': '东京','nrt': '东京','kr': '韩国','sel': '首尔','icn': '首尔',
        'us': '美国','lax': '洛杉矶','sfo': '旧金山','sea': '西雅图',
        'uk': '英国','lhr': '伦敦','man': '曼彻斯特','de': '德国','fra': '法兰克福','ber': '柏林',
        'tw': '台湾','tpe': '台北','khh': '高雄','mo': '澳门','mfm': '澳门',
        'th': '泰国','bkk': '曼谷','vn': '越南','sgn': '胡志明','han': '河内',
        'id': '印尼','cgk': '雅加达','ph': '菲律宾','mnl': '马尼拉','my': '马来西亚','kul': '吉隆坡',
        'in': '印度','bom': '孟买','maa': '金奈','au': '澳大利亚','syd': '悉尼',
        'fr': '法国','par': '巴黎','nl': '荷兰','ams': '阿姆斯特丹','ca': '加拿大','yvr': '温哥华','yyz': '多伦多',
        'ru': '俄罗斯','mow': '莫斯科','ae': '阿联酋','dxb': '迪拜','sa': '沙特','jed': '吉达',
        'za': '南非','jnb': '约翰内斯堡','br': '巴西','sao': '圣保罗','mx': '墨西哥','mex': '墨西哥城',
        'ar': '阿根廷','eze': '布宜诺斯艾利斯','it': '意大利','mxp': '米兰',
        'es': '西班牙','bcn': '巴塞罗那','ch': '瑞士','zrh': '苏黎世','se': '瑞典','arn': '斯德哥尔摩',
        'no': '挪威','osl': '奥斯陆','fi': '芬兰','hel': '赫尔辛基','pl': '波兰','waw': '华沙',
        'cz': '捷克','prg': '布拉格','at': '奥地利','vie': '维也纳','ie': '爱尔兰','dub': '都柏林',
        'pt': '葡萄牙','lis': '里斯本','gr': '希腊','ath': '雅典','il': '以色列','tlv': '特拉维夫',
        'tr': '土耳其','ist': '伊斯坦布尔'
    };
    const entries = sub.split(',').map(s => s.trim()).filter(s => s).slice(0, 4);
    const allIps = new Set();
    const allDomains = new Set();
    for (const entry of entries) {
        const match = entry.match(/^(ip|cf)-(.+)$/);
        if (!match) continue;
        const [, type, requestedUrl] = match;
        const url = safeSubscriptionUrl(requestedUrl, env);
        if (!url) continue;
        let content = null;
        const cacheKey = `https://dns-cache/sub/${encodeURIComponent(url)}`;
        const cached = subCache.get(url);
        // 1. 内存缓存
        if (cached && Date.now() < cached.expire) {
            content = cached.content;
        } else {
            // 2. Cache API（新增）
            const cachedText = await readCache(cacheKey);
            if (cachedText) {
                content = cachedText;
                subCache.set(url, { content, expire: Date.now() + SUB_CACHE_TTL });
            } else {
                 // 3. 远程下载（原有逻辑）
               try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 5000);
                try {
                    const res = await fetch(url, { signal: controller.signal, redirect: 'error' });
                    content = await limitedResponseText(res, 128 * 1024);
                } finally {
                    clearTimeout(timer);
                }
                if (content !== null) {
                    subCache.set(url, { content, expire: Date.now() + SUB_CACHE_TTL });
                     // 异步写入 Cache API（新增）
                    writeCache(cacheKey, content, SUB_CACHE_TTL / 1000);
                } else if (cached) {
                    content = cached.content;
                    cached.expire = Date.now() + SUB_CACHE_TTL; // 延长过期时间                
                }
            } catch (e) {
                console.error('sub fetch error:', e);
                if (cached){ 
                    content = cached.content;
                    cached.expire = Date.now() + SUB_CACHE_TTL;
                }   
              }
           }
        }
        if (!content || content.length > 128 * 1024) continue;
        const lines = content.split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .map(line => {
                let comment = '';
                const commentIndex = line.indexOf('#');
                if (commentIndex !== -1) {
                    comment = line.substring(commentIndex + 1).trim();
                    line = line.substring(0, commentIndex).trim();
                }
                if (areaFilter && comment) {
                    const commentLower = comment.toLowerCase();
                    const keywords = areaFilter.split(',').map(k => k.trim()).filter(k => k);
                    if (keywords.length > 0) {
                        const matched = keywords.some(keyword => {
                            if (commentLower.includes(keyword)) return true;
                            const chineseName = areaMap[keyword];
                            if (chineseName && comment.includes(chineseName)) return true;
                            return false;
                        });
                        if (!matched) return null;
                    }
                }
                return line;
            })
            .filter(item => item !== null)
            .map(line => {
                if (type === 'ip') {
                    if (line.startsWith('[') && line.includes(']:')) {
                        line = line.substring(1, line.indexOf(']:'));
                    } else if (line.includes(':')) {
                        const ipv4Port = line.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/);
                        if (ipv4Port) line = ipv4Port[1];
                    }
                } else {
                    const portIndex = line.lastIndexOf(':');
                    if (portIndex !== -1) {
                        const host = line.substring(0, portIndex);
                        const port = line.substring(portIndex + 1);
                        if (/^\d+$/.test(port)) line = host;
                    }
                }
                return line.trim();
            })
            .filter(line => line && !excludeItems.has(line));
        for (const line of lines) {
            if (type === 'ip') allIps.add(line);
            else allDomains.add(line);
        }
    }
    if (allIps.size > 0) config.ip4 = Array.from(allIps).slice(0, 256).join(',');
    if (config.ip4) config.ip4 = prescreenIpList(config.ip4);
    if (allDomains.size > 0) config.cfDomain = Array.from(allDomains).slice(0, 64).join(',');
  
}

// ===================== 辅助函数 =====================
function isDomainIpv4Only(domain) {
    return IPV4_ONLY_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
}

/**
 * 从上游 A/AAAA 记录获取真实 IP hints
 */
async function resolveRealHints(domain, type, clientIP) {
    try {
        const data = await queryUpstreamDNS(domain, type, clientIP);
        if (data && data.Answer) {
            return data.Answer.filter(r => r.type === type).map(r => r.data);
        }
    } catch (e) {}
    return [];
}

/**
 * 解析原始 HTTPS 记录（用于增强模式）
 */
function parseRawHttpsRecord(dataStr) {
    return parseSvcParamsFromData(dataStr);
}

/**
 * 完整解析 HTTPS 记录（用于 JSON API 返回）
 */
function parseHttpsRecordFull(dataStr) {
    const params = parseSvcParamsFromData(dataStr);
    const result = {};
    for (const p of params) {
        if (p.key === 'ech') result.ech = p.val;
        else if (p.key === 'alpn') result.alpn = p.val;
        else if (p.key === 'ipv4hint') result.ipv4hints = p.val.split(',').map(s => s.trim());
        else if (p.key === 'ipv6hint') result.ipv6hints = p.val.split(',').map(s => s.trim());
    }
    return Object.keys(result).length ? result : null;
}

/**
 * 返回 JSON 响应
 */
function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}
/**
 * 判断某条 DNS 记录类型（A 或 AAAA）是否被屏蔽
 * @param {string} type - 'A' 或 'AAAA'
 * @param {object|null} ruleObj - matchRule 返回的规则对象，未匹配则为 null
 * @param {object} config - 当前请求配置
 * @returns {boolean}
 */
function isTypeBlocked(type, ruleObj, config, isCF = false) {
    if (ruleObj) {
        if (type === 'A' && ruleObj.noA) return true;
        if (type === 'AAAA') {
            if (ruleObj.hasOwnProperty('noAAAA')) {
                return ruleObj.noAAAA;
            }
        }
    }
    // CF 站点默认禁用 IPv6（可通过 nocf6=false 开启）
    if (type === 'AAAA' && isCF && config.nocf6 !== 'false') {
        return true;
    }
    if (type === 'AAAA' && config.no6 === 'true') {
        return true;
    }
    return false;
}
function getHtml() {
    return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Doh-ECH · DNS 查询测试</title>
<style>
:root{color-scheme:dark;--bg:#0b1120;--panel:#111a2b;--field:#0c1423;--line:#26334a;--text:#eef2fa;--muted:#9baac0;--accent:#72aaff;--blue:#2969dc;--good:#68d5a7;--warn:#f4c77a;--bad:#ff9c9c;--radius:16px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}main{width:min(1050px,100%);margin:auto;padding:32px 20px 48px}a{color:var(--accent)}h1,h2,h3,p{margin:0}h1{font-size:28px;line-height:1.25;letter-spacing:-.04em}h2{font-size:18px}h3{font-size:15px}.muted{color:var(--muted);font-size:13px}.head{display:flex;align-items:center;gap:14px;margin-bottom:25px}.logo{width:46px;height:46px;flex:none;border-radius:13px;background:#1a365e;display:grid;place-items:center;color:var(--accent);font-size:24px;font-weight:700}.head p{margin-top:4px}.tag{font-size:12px;border:1px solid var(--line);border-radius:20px;padding:3px 10px;color:var(--muted);margin-left:auto;white-space:nowrap}.layout{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:16px;align-items:start}.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:20px;min-width:0}.panel+.panel{margin-top:16px}.section-head{margin-bottom:14px}.section-head p{margin-top:3px}.presets{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:20px}button,input,select{font:inherit}button{cursor:pointer}button:disabled{opacity:.6;cursor:wait}.preset{background:var(--field);border:1px solid var(--line);border-radius:11px;color:var(--text);text-align:left;padding:11px 12px;min-height:68px}.preset:hover,.preset:focus-visible{border-color:var(--accent)}.preset strong{display:block;font-size:14px}.preset small{color:var(--muted);font-size:12px;overflow-wrap:anywhere}label.field{display:block;min-width:0}label.field span{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}input:not([type=checkbox]),select{width:100%;min-width:0;min-height:44px;padding:9px 12px;background:var(--field);border:1px solid var(--line);border-radius:9px;color:var(--text)}input:focus,select:focus,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.form-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(125px,.65fr);gap:12px}.full{grid-column:1/-1}.actions{display:flex;gap:9px;margin-top:16px}.primary,.secondary{border:1px solid transparent;border-radius:10px;min-height:44px;padding:9px 15px;font-weight:600}.primary{background:var(--blue);color:white;flex:1}.secondary{background:transparent;color:var(--text);border-color:var(--line)}.primary:hover{filter:brightness(1.12)}.secondary:hover{border-color:var(--accent)}details.advanced{border-top:1px solid var(--line);margin-top:16px;padding-top:14px}summary{cursor:pointer;color:var(--accent);font-weight:600}details[open]>summary{margin-bottom:12px}.advanced-group{margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}.advanced-group h3{margin-bottom:10px}.checks{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0 6px}.checks label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}input[type=checkbox]{accent-color:var(--blue);width:17px;height:17px}.help{font-size:12px;color:var(--muted);margin:8px 0}.endpoint{padding:12px 0;border-bottom:1px solid var(--line)}.endpoint:last-of-type{border-bottom:0}.endpoint h3{margin-bottom:4px}.urlrow{display:flex;align-items:center;gap:8px;margin:9px 0}.urlrow code{flex:1;min-width:0;overflow-wrap:anywhere;font-size:12px;color:var(--accent);background:var(--field);border-radius:8px;padding:9px}.copy{flex:none;border:1px solid var(--line);border-radius:8px;color:var(--text);background:transparent;padding:8px 10px;font-size:13px}.client-help{margin-top:14px;padding-top:14px;border-top:1px solid var(--line)}.client-help p{margin-top:8px}.results{margin-top:16px}.result-grid{display:grid;grid-template-columns:1fr;gap:10px;margin-top:12px}.result-card{border:1px solid var(--line);border-radius:12px;background:var(--field);padding:14px;min-width:0}.result-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px}.status{font-size:12px;font-weight:600;color:var(--muted);text-align:right}.status.good{color:var(--good)}.status.warn{color:var(--warn)}.status.bad{color:var(--bad)}.values{display:flex;flex-wrap:wrap;gap:6px;margin:9px 0}.values code{font-size:12px;overflow-wrap:anywhere;max-width:100%;padding:5px 8px;border:1px solid var(--line);border-radius:7px;color:var(--text)}.data-line{font-size:13px;overflow-wrap:anywhere;color:var(--muted);margin-top:5px}.raw{margin-top:14px}pre{background:var(--field);border:1px solid var(--line);padding:12px;border-radius:10px;max-height:360px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,monospace}.note{margin:10px 0 0;font-size:13px;color:var(--muted)}.footer{margin-top:20px;color:var(--muted);font-size:12px;text-align:center}.feedback{min-height:20px;color:var(--muted);font-size:12px;margin-top:4px}.busy{color:var(--accent)}[hidden]{display:none!important}
@media(max-width:760px){main{padding:20px 12px 32px}.layout{grid-template-columns:1fr}.panel{padding:16px}.head{margin-bottom:18px}.tag{display:none}h1{font-size:24px}}@media(max-width:380px){.form-grid{grid-template-columns:1fr}.presets{grid-template-columns:1fr 1fr}.preset{padding:8px}.urlrow{align-items:flex-start}}@media(prefers-color-scheme:light){:root{color-scheme:light;--bg:#f2f5fa;--panel:#fff;--field:#f5f7fc;--line:#d8e0ee;--text:#17243a;--muted:#53657e;--accent:#1c5bb8;--blue:#235fc7;--good:#087b51;--warn:#946200;--bad:#b4232c}.logo{background:#e3edff}}
</style>
</head>
<body><main>
<header class="head"><div class="logo" aria-hidden="true">↯</div><div><h1>Doh-ECH 查询测试</h1><p class="muted">一键检查 DNS、IPv4 / IPv6 与 ECH，复制自己的 DoH 地址。</p></div><span class="tag">自托管 DNS</span></header>
<div class="layout"><div>
<section class="panel" aria-labelledby="quick-title">
<div class="section-head"><h2 id="quick-title">快速测试</h2><p class="muted">点击任意测试场景，立即查询；不需要填写高级参数。</p></div>
<div class="presets">
<button type="button" class="preset" data-domain="github.com" data-type="all" data-enhance="off"><strong>普通 DNS</strong><small>GitHub · IPv4 / IPv6 / HTTPS</small></button>
<button type="button" class="preset" data-domain="cloudflare.com" data-type="HTTPS" data-enhance="off"><strong>Cloudflare ECH</strong><small>检查加密客户端问候配置</small></button>
<button type="button" class="preset" data-domain="www.facebook.com" data-type="HTTPS" data-enhance="off"><strong>Meta ECH</strong><small>Facebook · ECH 来源</small></button>
<button type="button" class="preset" data-domain="google.com" data-type="AAAA" data-enhance="rule"><strong>Google IPv6</strong><small>启用规则增强，查询 AAAA</small></button>
<button type="button" class="preset" data-domain="mtalk.google.com" data-type="A" data-enhance="rule"><strong>Android 推送</strong><small>FCM · 检查 IPv4 解析</small></button>
<button type="button" class="preset" data-domain="taobao.com" data-type="A" data-enhance="off"><strong>国内解析</strong><small>淘宝 · 检查普通 A 记录</small></button>
<button type="button" class="preset" data-domain="www.google.com" data-type="all" data-enhance="direct"><strong>Google 直连诊断</strong><small>真实 IPv4 / IPv6 / HTTPS</small></button>
<button type="button" class="preset" data-domain="x.com" data-type="all" data-enhance="direct"><strong>X 直连诊断</strong><small>真实地址与原生 HTTPS</small></button>
</div>
<form id="queryForm">
<div class="form-grid">
<label class="field full"><span>查询域名（也可以粘贴网站网址）</span><input id="domain" value="github.com" placeholder="例如 github.com" autocomplete="off" autocapitalize="none" spellcheck="false" required></label>
<label class="field"><span>记录类型</span><select id="type"><option value="all">全部：A / AAAA / HTTPS</option><option value="A">A · IPv4</option><option value="AAAA">AAAA · IPv6</option><option value="HTTPS">HTTPS · ECH</option><option value="CNAME">CNAME · 别名</option><option value="TXT">TXT · 文本</option><option value="MX">MX · 邮件</option><option value="NS">NS · 域名服务器</option></select></label>
<label class="field"><span>解析模式</span><select id="enhance"><option value="off">默认解析</option><option value="balanced">日常均衡（推荐）</option><option value="rule">规则增强</option><option value="full">全局增强</option><option value="direct">Google / X 原生直连</option></select></label>
</div>
<p class="help">日常均衡：国内外分流，保留完整原生 DNS 应答；不应用高级改写参数。默认模式仍保留 Cloudflare / Meta 的内置 ECH 策略；规则增强可能改变 DNS 地址，请在实际网络验证。纯转发请使用右侧 /doh。</p>
<p class="help">Google / X 原生直连：仅针对 Google、X 及相关资源域名，优先真实 DNS，保留 IPv4/IPv6 和原生 HTTPS 记录，不使用随机 IP 或全局优选；其他域名保持默认策略。此模式下目标域名不应用高级地址覆盖。</p>
<details class="advanced" id="advanced"><summary>高级设置（可选） <span id="advancedCount" class="muted"></span></summary>
<p class="muted">以下参数都可组合使用；关闭面板不会取消设置，点击重置即可恢复默认。</p>
<div class="advanced-group"><h3>Cloudflare 优选</h3><div class="form-grid">
<label class="field"><span>IPv4 · ip4</span><input id="ip4" placeholder="逗号分隔的 IPv4 地址"></label>
<label class="field"><span>IPv6 · ip6</span><input id="ip6" placeholder="逗号分隔的 IPv6 地址"></label>
<label class="field"><span>优选域名 · cf</span><input id="cf" placeholder="example.com"></label>
<label class="field"><span>ECH 来源 · ech</span><input id="ech" placeholder="cloudflare-ech.com"></label>
<label class="field full"><span>优选订阅 · sub</span><input id="sub" placeholder="ip-https://… 或 cf-https://…"></label>
<label class="field"><span>排除项 · exclude</span><input id="exclude" placeholder="IP 或域名，逗号分隔"></label>
<label class="field"><span>地区 · area</span><input id="area" placeholder="hk / jp / sg"></label>
</div><p class="help">订阅来源需由服务端管理员授权；未授权的来源不会被下载。</p></div>
<div class="advanced-group"><h3>Meta 优选</h3><div class="form-grid">
<label class="field"><span>IPv4 · metaIp4</span><input id="metaIp4" placeholder="逗号分隔的 IPv4 地址"></label>
<label class="field"><span>IPv6 · metaIp6</span><input id="metaIp6" placeholder="逗号分隔的 IPv6 地址"></label>
<label class="field full"><span>优选域名 · meta</span><input id="meta" placeholder="example.com"></label>
</div></div>
<div class="advanced-group"><h3>规则与协议</h3><div class="form-grid">
<label class="field full"><span>自定义规则 · rules（规则或全局增强时生效）</span><input id="rules" placeholder="*.example.com:1.2.3.4-noAAAA"></label>
<label class="field"><span>ALPN · alpn</span><input id="alpn" value="h3,h2"></label>
<label class="field"><span>必需参数 · mandatory</span><input id="mandatory" value="alpn"></label>
<label class="field full"><span>客户端地址 · clientIp（ECS，留空自动获取）</span><input id="clientIp" placeholder="可选，IPv4 或 IPv6"></label>
</div><div class="checks">
<label><input type="checkbox" id="best"> 全局跟随优选</label>
<label><input type="checkbox" id="no6"> 禁用 IPv6（规则可覆盖）</label>
<label><input type="checkbox" id="allowCF6"> 允许 CF IPv6</label>
<label><input type="checkbox" id="shuffle" checked> 随机排列地址</label>
</div><p class="help">全局跟随优选会主动探测 CDN 归属；CF IPv6 默认关闭。ECS 可能向上游透露大致网络位置。</p></div>
<div class="advanced-group"><h3>本机验证地址（Google / X 原生直连模式）</h3><label class="field"><span>X HTTP/3 实测 IPv4 · xh3</span><input id="xh3" placeholder="172.66.0.227"></label><p class="help">仅 x.com 生效：填写本机通过 HTTP/3 证书与 HTTP 响应验证的 IPv4，生成 A 与 HTTPS（h3,h2）记录。浏览器仍自行选择协议；不改变其他域名、不注入 ECH。网络变化后重新验证。</p><label class="field"><span>本机测速结果 · pins</span><input id="pins" placeholder="www.google.com=IPv6地址;x.com=IPv4地址"></label><p class="help">仅覆盖指定域名和地址族，按本机实测顺序返回；未设置的域名及地址族仍用原生 DNS。请只填自己实际通过 TLS 证书验证和 HTTP 测试的地址，网络变化后重新测试。<a href="https://github.com/wxcvm/Doh-ECH/blob/main/scripts/direct-probe.py" target="_blank" rel="noopener noreferrer">本机检测脚本</a></p></div>
</details>
<div class="actions"><button class="primary" id="queryBtn" type="submit">开始查询</button><button class="secondary" id="resetBtn" type="button">重置</button></div>
<div class="feedback" id="feedback" role="status" aria-live="polite"></div>
</form></section>
<section class="panel results" id="results" hidden aria-labelledby="resultsTitle"><div class="section-head"><h2 id="resultsTitle">查询结果</h2><p class="muted" id="resultSummary"></p></div><div id="cards" class="result-grid" aria-live="polite"></div><p class="note">有 IP 或 ECH 配置表示 DNS 返回了记录，不等于网站可达、TLS ECH 握手成功或手机推送已恢复。</p><p class="note">请先关闭代理（含 TUN/VPN），将当前 ECH 地址设为浏览器安全 DNS，再打开 <a href="https://www.google.com/" target="_blank" rel="noopener noreferrer">Google</a> 或 <a href="https://x.com/" target="_blank" rel="noopener noreferrer">X</a> 验证本机连接。网页不能替你关闭代理。</p><details class="raw"><summary>查看原始 JSON</summary><pre id="rawJson"></pre></details></section>
</div>
<aside><section class="panel" aria-labelledby="address-title"><div class="section-head"><h2 id="address-title">你的 DoH 地址</h2><p class="muted">查询域名只用于测试；复制下面的地址配置客户端，参数会随设置更新。</p></div>
<div class="endpoint"><h3>日常均衡 · 推荐</h3><p class="muted">国内阿里 / DNSPod，国际 Cloudflare / Google；原生 DNS，不强制改写 IP、ECH 或协议。</p><div class="urlrow"><code id="balancedUrl"></code><button class="copy" type="button" data-copy="balancedUrl">复制</button></div></div><div class="endpoint"><h3>纯 DoH · 兼容</h3><p class="muted">原样转发上游，不注入 ECH 或优选 IP。</p><div class="urlrow"><code id="dohUrl"></code><button class="copy" type="button" data-copy="dohUrl">复制</button></div></div>
<div class="endpoint"><h3>ECH 增强 · 当前设置</h3><p class="muted">Cloudflare / Meta ECH，支持自定义增强规则。</p><div class="urlrow"><code id="echUrl"></code><button class="copy" type="button" data-copy="echUrl">复制</button></div></div>
<div class="feedback" id="copyStatus" role="status" aria-live="polite"></div>
<div class="client-help"><h3>怎么配置客户端？</h3><p class="muted"><strong>直连地址筛选：</strong>用 <a href="https://github.com/wxcvm/Doh-ECH/blob/main/scripts/direct-probe.py" target="_blank" rel="noopener noreferrer">本机检测脚本</a> 在关闭代理后测量 TCP、TLS 和 HTTP，再使用输出的专属 DoH 地址。</p><p class="muted"><strong>浏览器：</strong>安全 DNS / DNS over HTTPS，选择自定义并粘贴地址。</p><p class="muted"><strong>AdGuard：</strong>DNS 保护 → DNS 服务器 → 添加自定义服务器，粘贴 DoH 地址。</p><p class="muted"><strong>Android：</strong>系统「私人 DNS」通常使用 DoT 主机名，不接受 HTTPS URL；请用支持 DoH 的客户端。</p><p class="muted">若同时使用代理 Fake-IP DNS，建议先确认 DNS 分工，不要让多个组件重复接管。</p></div>
</section></aside></div>
<footer class="footer">Doh-ECH · Cloudflare Workers · <a href="https://github.com/wxcvm/Doh-ECH" target="_blank" rel="noopener noreferrer">项目仓库</a> · <a href="https://github.com/rosenii/Doh-ECH" target="_blank" rel="noopener noreferrer">上游项目</a></footer>
</main>
<script>
(function(){
'use strict';
const $=id=>document.getElementById(id);
const form=$('queryForm');
const fields=['ip4','ip6','cf','ech','sub','exclude','area','metaIp4','metaIp6','meta','rules','clientIp'];
const typeNames={A:'IPv4 地址',AAAA:'IPv6 地址',HTTPS:'HTTPS / ECH',CNAME:'CNAME 别名',TXT:'TXT 文本',MX:'MX 邮件',NS:'NS 服务器'};
const modeNames={off:'默认解析',balanced:'日常均衡',rule:'规则增强',full:'全局增强',direct:'Google / X 原生直连'};
let busy=false;
function params(){
 const p=new URLSearchParams();
 if($('enhance').value==='balanced'){p.set('enhance','balanced');return p;}
 for(const key of fields){const v=$(key).value.trim();if(v)p.set(key,v);}
 if($('enhance').value!=='off')p.set('enhance',$('enhance').value);
 if($('enhance').value==='direct'&&$('pins').value.trim())p.set('pins',$('pins').value.trim());
 if($('enhance').value==='direct'&&$('xh3').value.trim())p.set('xh3',$('xh3').value.trim());
 for(const [key,def] of [['alpn','h3,h2'],['mandatory','alpn']]){const v=$(key).value.trim();if(v&&v!==def)p.set(key,v);}
 if($('best').checked)p.set('best','true');
 if($('no6').checked)p.set('no6','true');
 if($('allowCF6').checked)p.set('nocf6','false');
 if(!$('shuffle').checked)p.set('shuffle','false');
 return p;
}
function refreshUrls(){
 const p=params();$('balancedUrl').textContent=location.origin+'/ech?enhance=balanced';$('dohUrl').textContent=location.origin+'/doh';
 $('echUrl').textContent=location.origin+'/ech'+(p.size?'?'+p.toString():'');
 $('advancedCount').textContent=p.size?'· '+p.size+' 项非默认设置':'· 默认';
}
function resetSettings(){form.reset();$('advanced').open=false;refreshUrls();$('feedback').textContent='';}
function normalizedDomain(raw){
 let value=raw.trim();
 if(!value)return '';
 if(/^https?:\\/\\//i.test(value)){const u=new URL(value);value=u.hostname;}
 value=value.replace(/\\.$/,'');
 if(/[^\\x00-\\x7f]/.test(value))value=new URL('https://'+value).hostname;
 value=value.toLowerCase();
 if(value.length>253||!value.split('.').every(v=>v.length>0&&v.length<=63&&/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(v)))throw new Error('请输入有效域名，例如 github.com（不含端口或路径）');
 return value;
}
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n;}
function line(card,text){card.append(el('p','data-line',text));}
function values(card,arr){if(!Array.isArray(arr)||!arr.length)return;const box=el('div','values');for(const value of arr)box.append(el('code','',value));card.append(box);}
function cardFor(type,out){
 const card=el('article','result-card');card.dataset.type=type;
 const title=el('div','result-title');title.append(el('h3','',typeNames[type]||type));
 let status='已返回记录',tone='good',description='';
 const d=out.data;
 if(out.error){status='查询失败';tone='bad';description=out.error;}
 else if(d.rcode===3){status='域名不存在';tone='warn';description='上游返回 NXDOMAIN（RCODE 3）。';}
 else if(d.rcode!==undefined&&d.rcode!==0){status='解析失败';tone='bad';description='DNS 错误码 '+d.rcode+'，可以稍后重试。';}
 else if(type==='HTTPS'){
  if(d.policy==='x-http3'){status='已声明 HTTP/3';description='DNS 已声明 h3,h2；需要实际浏览器连接验证，不代表 ECH 已启用。';}
  else if(d.ech){status='已取得 ECH 配置';description=d.echSource==='legacy-meta'?'使用 Meta 兼容配置，需实际握手验证。':'已取得 ECH 配置，是否接受仍需实际握手验证。';}
  else{status='未取得 ECH';tone='warn';description='未返回 ECH 配置，不一定表示域名异常。';}
 }else if(!Array.isArray(d.answers)||!d.answers.length){status='无此类记录';tone='warn';description='可能是域名未发布该记录，或当前解析策略屏蔽了此类型。';}
 else{description='DNS 返回 '+d.answers.length+' 条记录。';}
 title.append(el('span','status '+tone,status));card.append(title,el('p','muted',description));
 if(d){if(d.policy==='balanced-domestic')line(card,'解析策略：日常均衡 · 国内上游');if(d.policy==='balanced-international')line(card,'解析策略：日常均衡 · 国际上游');if(d.policy==='balanced-fallback')line(card,'解析策略：日常均衡 · 国内故障回退');if(d.policy==='native-direct')line(card,'解析策略：原生 DNS（未替换地址）');if(d.policy==='local-pins')line(card,'解析策略：本机指定地址（服务器未验证你的网络）');if(d.policy==='x-http3')line(card,'解析策略：X HTTP/3 实验配置（浏览器自行选择协议）');if(d.alpn)line(card,'ALPN：'+d.alpn);values(card,d.answers);if(d.ipv4hints?.length){line(card,'IPv4 提示');values(card,d.ipv4hints);}if(d.ipv6hints?.length){line(card,'IPv6 提示');values(card,d.ipv6hints);}if(d.echSource)line(card,'ECH 来源：'+(d.echSource==='legacy-meta'?'Meta 兼容配置':d.echSource==='dns'?'DNS 动态配置':d.echSource));if(Number.isFinite(d.ttl))line(card,'TTL：'+d.ttl+' 秒');}
 if(Number.isFinite(out.ms))line(card,'查询耗时：'+out.ms+' ms（浏览器到服务的请求时间）');
 return card;
}
async function queryOne(domain,type,settings){
 const p=new URLSearchParams(settings);p.set('domain',domain);p.set('type',type);
 const start=performance.now();const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),15000);
 try{const r=await fetch('/api/query?'+p.toString(),{signal:controller.signal});const data=await r.json();if(!r.ok||data.error)throw new Error(data.error||'HTTP '+r.status);return {type,data,ms:Math.round(performance.now()-start)};}
 catch(err){return {type,error:err.name==='AbortError'?'查询超时，请重试。':String(err.message||err),ms:Math.round(performance.now()-start)};}
 finally{clearTimeout(timer);}
}
async function run(){
 if(busy)return;
 let domain;try{domain=normalizedDomain($('domain').value);if(!domain)throw new Error('请输入查询域名');}catch(err){$('feedback').textContent=err.message;$('domain').focus();return;}
 $('domain').value=domain;
 const settings=params();const type=$('type').value;const types=type==='all'?['A','AAAA','HTTPS']:[type];
 const mode=$('enhance').value;busy=true;$('queryBtn').disabled=true;$('queryBtn').textContent='查询中…';
 document.querySelectorAll('.preset,#resetBtn').forEach(b=>b.disabled=true);
 $('feedback').textContent='正在查询 '+domain+'…';$('results').hidden=false;$('resultSummary').textContent=domain+' · '+modeNames[mode]+' · 查询中';
 $('cards').replaceChildren();$('rawJson').textContent='';
 try{
  const outcomes=await Promise.all(types.map(t=>queryOne(domain,t,settings)));
  $('cards').replaceChildren(...outcomes.map(o=>cardFor(o.type,o)));
  $('rawJson').textContent=JSON.stringify(outcomes.map(o=>o.data||{type:o.type,error:o.error}),null,2);
  const completed=outcomes.filter(o=>!o.error&&(!o.data.rcode||o.data.rcode===0)).length;
  $('resultSummary').textContent=domain+' · '+modeNames[mode]+' · '+completed+'/'+types.length+' 项正常返回';
  $('feedback').textContent='查询完成。结果在下方。';
  if(matchMedia('(max-width:760px)').matches) $('results').scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
 }finally{busy=false;$('queryBtn').disabled=false;$('queryBtn').textContent='开始查询';document.querySelectorAll('.preset,#resetBtn').forEach(b=>b.disabled=false);}
}
async function copy(id){
 const value=$(id).textContent;
 try{await navigator.clipboard.writeText(value);}
 catch{const input=document.createElement('textarea');input.value=value;input.style.position='fixed';input.style.opacity='0';document.body.append(input);input.select();let ok=false;try{ok=document.execCommand('copy');}finally{input.remove();}if(!ok)throw new Error('无法自动复制，请长按地址手动复制。');}
}
form.addEventListener('submit',e=>{e.preventDefault();run();});
form.addEventListener('input',refreshUrls);form.addEventListener('change',refreshUrls);
$('resetBtn').addEventListener('click',()=>{resetSettings();$('results').hidden=true;});
document.querySelectorAll('.preset').forEach(btn=>btn.addEventListener('click',()=>{resetSettings();$('domain').value=btn.dataset.domain;$('type').value=btn.dataset.type;$('enhance').value=btn.dataset.enhance;refreshUrls();run();}));
document.querySelectorAll('[data-copy]').forEach(btn=>btn.addEventListener('click',async()=>{try{await copy(btn.dataset.copy);$('copyStatus').textContent='已复制 DoH 地址。';}catch(e){$('copyStatus').textContent=e.message;}}));
refreshUrls();
})();
</script>
</body></html>`;
}
