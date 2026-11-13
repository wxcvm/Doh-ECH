# DOH-ECH ：私人DOH服务器+HTTPS RR控制器 + ECH注入器

 **个人 DNS-over-HTTPS (DoH) 服务器**:
 
 **1.基于ECH拓展**： 
     智能为 Cloudflare / Meta 站点HTTPS RR 注入 ECH 配置
     
 **2.利用QUIC Client Initial 分片**: 
     Chrome/Firefox以及代理客户端等多已支持，为支持quic协议的网站返回alpn=h3，为指定站点返回alpn:h3,仅ipv6hints的HTTPS记录并屏蔽A记录等
     
---
## 警告
本项目由AI生成，仅供娱乐目的， **不得用于非法用途，请遵守当地法律法规合理学习和使用**，用于违反当地法律法规的非法用途造成的后果与本人本项目无关！

---

## 路由说明

| 路径          | 说明                                                                 |
| ------------- | -------------------------------------------------------------------- |
| `/`           | 前端测试查询页面，提供域名输入、类型选择与高级选项。                      |
| `/api/query`  | JSON API，通过 URL 参数查询并返回结构化结果（支持所有自定义参数）。    |
| `/ech`        | DoH 端点，返回注入 ECH 配置/增强构造的HTTPS RR（支持参数与请求头传参）。          |
| `/doh`        | DoH 端点，纯净上游转发，不作任何修改  |
| `/log`           | 管理员状态接口（需要 `DOH_ADMIN_TOKEN` Bearer 认证）。  
---

> **端点行为说明**
> - `/ech`、`/doh`、`/dns-query` 均为标准 **RFC8484 DoH 端点**：只接受 `POST` + `Content-Type: application/dns-message`，或 `GET ?dns=<base64url>`。缺少 `?dns=` 的 GET 返回 **400**（旧版返回 200 `OK`，会让配置错误的客户端把空响应当成有效结果）。需要 JSON 查询请用 `/api/query`。
> - `/ech` 只合成 **A / AAAA / HTTPS** 三类记录；其余类型（TXT/MX/NS/SRV/CAA/SOA…）原样转发上游，不会被按 A 解析成畸形记录。
> - 未知路径返回 **404 JSON**（旧版会把任意路径都渲染成首页）；支持 `OPTIONS` CORS 预检。
> - 事务 ID 与 EDNS0 OPT 一律在响应时按**当前请求**回写/追加，缓存体固定为「ID=0 且不含 OPT」的规范形式：不会把某个客户端的事务 ID、OPT（含 COOKIE）或 `ip4`/`ip6`/`no6`/`enhance`/`ech` 等参数的结果带给其他客户端。
> - `/ech` 仅对结果与自定义参数无关的静态请求缓存合成的 DNS 结果；`/doh` 直接转发上游完整 DNS 响应，不复用仅由域名和类型决定的自定义缓存。对客户端的 DNS HTTP 响应使用 `Cache-Control: no-store`。
> - 上游返回 NXDOMAIN 时透传 RCODE=3；如果二进制 DoH 的所有上游都失败，返回 DNS SERVFAIL，而非把 HTML 错误页当作 DNS 报文。
## Enhance Mode 功能与使用

### Google / FCM 上游规则同步（2026-11-13）

- 在 `enhance=rule/full` 下扩展 Google 地区域名（如 google.co.jp、google.de、google.com.au）并沿用现有 Google IPv6 增强策略。
- FCM 推送域名（mtalk.google.com、mobile-gtalk.l.google.com、各 alt*-mtalk 等）保留真实 A/AAAA，不套用通用 Google IPv6-only 规则。
- YouTube Music、robinfrontend-pa.googleapis.com、signaler-pa.googleapis.com 和 dl.google.com 使用真实 IPv4，屏蔽 AAAA 与 IPv6 hints；仅在增强模式开启时生效。DNS 策略不能保证目标服务可直接访问。
- 规则按域名具体程度匹配，同一域名的精确规则优先于通配规则；屏蔽策略同时作用于地址记录与合成 HTTPS hints。规则模式下未命中的普通域名保持原始 HTTPS 记录。
- 默认 `enhance=off`、`nocf6=true` 不变；需要 Cloudflare IPv6 的客户端可显式设置 `nocf6=false`，并在实际网络上验证。离线测试覆盖 AAAA 和 HTTPS hints 的开关行为，但不代表真实网络端到端连接已验证。

增强模式是 DoH-ECH 的一项高级功能，允许您为网站主动注入连接优化参数，例如强制 QUIC (HTTP/3)、提供自定义 IP 提示 (IP hints) 以及精确屏蔽 A/AAAA 记录。这不仅能加速网站访问，还能解决某些浏览器因协议偏好导致的连接失败问题。

> **注意**：增强模式规则**不会影响**静态列表中的 Cloudflare/Meta 域名，这些站点的 ECH 注入和优选 IP 逻辑独立运行，仅在规则列表里**特意添加CF/Meta域名规则**时才会生效(优先级:`ips[不为空]`>`cf/meta优选结果`>`ips[空]`)。

### 模式状态
增强模式通过 `enhance` 参数控制，共有三种状态：

| 状态 | 值 | 行为 |
|------|----|------|
| **关闭** | `off` (默认) | 不进行任何增强，普通域名保持上游原始记录。 |
| **规则模式** | `rule` | 仅对匹配**规则**的域名生效，未匹配域名保持原样。 |
| **全局模式** | `full` | 对所有普通域名生效。规则匹配的域名优先使用规则 IP，未匹配的从上游获取。 |

### 增强内容
开启增强模式后，匹配到的域名将获得以下优化：

**自定义 SVCB_PARAM**
- **ALPN 强制**：HTTPS 记录中注入 `alpn="h3,h2"`，引导浏览器优先使用 QUIC (HTTP/3)，失败时可回退 HTTP/2。可通过 `alpn` 参数自定义（如 `h3` 仅 QUIC）。
- **mandatory 指定**：指定哪些 HTTPS 参数必须被客户端理解，否则客户端应忽略整条 HTTPS 记录
- **no-default-alpn** ：强制浏览器绝不能使用 alpn 列表之外的任何“默认”协议作为备选或回退(遗憾：所有浏览器均不支持此参数)
- **IP Hints 注入**：HTTPS 记录中添加 `ipv4hint` 和/或 `ipv6hint`，浏览器可直接尝试这些 IP 建立连接，跳过 A/AAAA 查询。
  
**自定义规则**  
- **A/AAAA 记录屏蔽**：可通过规则标志 `noA` 或 `noAAAA` 完全屏蔽对应类型的 DNS 查询，强制浏览器依赖 hints 或仅使用特定 IP 版本。
-  **读取自定义远程hosts**

### 规则格式
增强模式的核心是**规则**，用于精确指定需要优化的域名及其参数。
#### 内置增强规则模板 (BUILTIN_HINTS)
此文档为 `_worker.js` 中 `BUILTIN_HINTS` 常量的配置指南。所有规则均支持通配符 `*`，且可配置 `noA` / `noAAAA` 标志及 IP 列表或 IPv6 前缀。

```javascript
const BUILTIN_HINTS = {

    // 写法一：对象形式，支持屏蔽标志和 IP 列表
    {
        domains:["*.domain1.com","domain2.com"],
        ips: ["1.2.3.4", "2001:db8::/32"],  // 可使用 IPv6 前缀（/32 等）
        noA: true,                          // 屏蔽 A 记录（仅 IPv6）
        noAAAA: false                       // 允许 AAAA 记录
    }
    //写法二：从远程读取hosts文件
    {
        hosts:["https://hosts1.txt","https://hosts2.json"],
        noA:flase, noAAAA: true
    },
};
hosts文件支持两种格式：
[
  ["8.8.8.8","dns.google"],
  ["8.8.8.8","dns.google"]
]
[
  { "domain":"dns.google","ip":"8.8.8.8"},
  { "domain":"dns.google","ip":"8.8.8.8"}
]

```
#### 通过`rules` 参数或`X-Rules`请求头参数配置
- **域名**：必填，支持通配符 `*.`（匹配所有子域及根域）。可逗号分隔多个域名。
- **IP列表**：可选，多个 IP 用逗号分隔，支持 IPv4/IPv6。留空表示不提供自定义 IP。
- **标志**：可选，使用 `-` 分隔，支持 `noA`（屏蔽 A 记录）、`noAAAA`（屏蔽 AAAA 记录）。可同时使用。

**示例**：
`*.google.com:2001:4860:4827:7700::,142.250.80.78-noA`
`google.com,google.com.hk:-noA-noAAAA`


## 自定义参数

所有参数均可通过 **URL 查询字符串** 或 **HTTP 请求头** 传入（请求头 `X-Ip4` 等）。

| 参数名        | 用途                                                                                     | 示例值                              |
| ------------- | ---------------------------------------------------------------------------------------- | ----------------------------------- |
| `ip4`         | CF 优选IPv4 替换地址                                    | `1.2.3.4,5.6.7.8`                  |
| `ip6`         | CF优选 IPv6 替换地址                                                     | `::1,::2`                           |
| `metaIp4`     | Meta 优选IPv4 替换地址                                                                 | `157.240.1.1`                       |
| `metaIp6`     | Meta 优选IPv6 替换地址                                                                 | `2a03:2880:...`                     |
| `cf`          | 解析优选域名 **仅对CF相关域名生效**        | `example.com,ip2.example.com`       |
| `meta`          | 解析优选域名 **仅对Meta相关域名生效**        | `example.com,ip2.example.com`       |
| `ech`         | 获取CF公共ECH配置的域名（默认 `cloudflare-ech.com`）                                      | `cloudflare-ech.com`               |
| `best` | 全局跟随优选 所有CF/META站点都使用优选IP 默认`false`|（`true`/`false`） | `false` |
| `clientIp` | 自定义 ECS；IPv4 /24、IPv6 /56 规范化网段 | 默认自动获取 | `192.0.2.123` |
| `sub` | CF优选订阅链接 |格式（`ip-https://ip.txt`/ `cf-https://domain.txt` ） |``|
| `exclude` | 返回记录排除指定ip/domain |（`1.1.1.1`/ `cf.cf` ） |``|
| `shuffle` |  乱序返回记录 |默认`true`（`false`/`true` ） |`false`|
| `area` |  指定ip区域 |留空`不过滤`（`area=hk,sg,jp` ） |``|
| `enhance` |  增强模式 |可选`off` `rule` `full`  默认`off`  |``|
| `rules` |  增强模式域名ip匹配规则 |格式`*.domain1,*.domain2:ip1,ip2-noA-noAAAA`（`-noA/AAAA`屏蔽且不返回A/AAAA记录 ） |``|
| `alpn` |  alpn列表 |默认 `h3,h2`     |``|
| `no6` |  全局屏蔽AAAA记录 |默认 `false`     |``|
| `nocf6` |  屏蔽CF AAAA记录 |默认 `true`     |``|

> **ClientIP自动获取逻辑：部分客户端DNS请求获取不到CF-Connecting-IP，请主动填入clientIp**
```
客户端
  │
  │ DoH 请求
  ▼
Cloudflare Edge
  │
  │ 注入 CF-Connecting-IP
  ▼
Cloudflare Worker
  │
  │ 读取 CF-Connecting-IP
  ▼
构造 EDNS Client Subnet (ECS)
  │
  ▼
上游 DNS（Google Public DNS 等）
```

---
## 安全部署（2026-10 安全修复）

本仓库的 `/ech` 是会修改 DNS 应答的实验性解析服务，**不要把它当作透明 DNSSEC 代理或所有网站都能使用的 ECH 加速器**。建议先用 `/doh` 验证兼容性，再按域名启用 `/ech` 和 `enhance=rule`。

### 私有状态接口

在 Cloudflare Workers 的密钥/环境变量中设置 `DOH_ADMIN_TOKEN`（请使用足够长的随机值；不要写入 Git 仓库）：

```sh
npx wrangler secret put DOH_ADMIN_TOKEN
curl -H 'Authorization: Bearer <YOUR_TOKEN>' https://YOUR_WORKER_DOMAIN/log
```

未配置密钥、未附带 Bearer 令牌，均返回 404。公开运行状态不应该暴露订阅地址路径，因为密钥可能出现在路径中。

### 开放远程优选 IP 订阅（显式允许）

出于安全原因，`sub=ip-https://...` 和对应的 `X-Sub` 自定义 URL **默认禁用**。如确需使用，在 Worker 配置 `DOH_ALLOWED_SUB_HOSTS`，其值为你信任的、逗号分隔的**精确域名**，例如 `feeds.example.com,raw.githubusercontent.com`。只允许 HTTPS（默认 443 端口）、拒绝重定向，并对订阅数量及响应大小设上限。该白名单**不是**针对订阅文件路径的权限控制：允许的主机仍可以提供不同路径的内容，请仅信任真正可信的源。

```toml
[vars]
DOH_ALLOWED_SUB_HOSTS = "feeds.example.com"
```

可将该配置放入你的 Wrangler 配置，也可在 Workers 控制台配置环境变量。不要随意将开放的用户内容平台加入允许列表。此前已部署的 `sub` 参数若没有配置此变量，将不会加载外部订阅；默认值是刻意选择的安全回退。

### 其他部署提醒

- 对公网端点配置 Cloudflare WAF 的速率限制、防滥用措施和告警；Worker 内的内存 Map 并不是可靠的跨边缘节点速率限制方案。
- POST 必须使用 `Content-Type: application/dns-message`，请求体最多 65,535 字节；GET `dns` 参数必须符合 base64url 格式。
- 对非 Cloudflare 自有域名，默认保留上游地址记录；`best=true`、`rules`、`ip4` 等显式增强选项仍可能改写连接地址，启用前须验证端到端连通性。
- DNSSEC DO 位、非 IN 类别及多问题查询会尽量以原始二进制查询转发上游，避免自构造结果丢失 DNSSEC 语义。
- 使用 `node --experimental-default-type=module tests/smoke.mjs` 运行基本回归测试。GitHub PR 自动触发 `doh-tests.yml`；通过测试不代表 DNSSEC/ECH 的所有边界情况均已覆盖。
- 不要把其他项目的 APK Release 当成 DoH Worker 发行版；此仓库的 Release 目前还被用于同步 `wxcvm/AdAway` 的更新源。

## 部署步骤

> ⚠️ 本项目是**纯 Worker 项目**（无静态文件），**不要**把 Pages 构建命令设置为 `npx wrangler deploy`，否则会报错 `Could not detect a directory containing static files`。

### 方式一：部署到 Cloudflare Workers（推荐）
- 本地安装 wrangler 后执行（`wrangler.toml` 已配置好 `main = "_worker.js"`）：
  ```bash
  npm i -g wrangler
  wrangler login
  wrangler deploy
  ```
- 或在 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **创建 Worker** → 粘贴 `_worker.js` 全部内容 → 部署。

### 方式二：部署到 Cloudflare Pages（连接 Git 仓库）
- 进入 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **Pages** → **创建项目** → 连接本仓库。
- 项目设置关键点（根目录存在 `_worker.js` 时会自动启用 **Advanced Mode 单 Worker 模式**）：
  - **构建命令（Build command）：留空**（不要填 `npx wrangler deploy`）
  - **构建输出目录（Build output directory）：留空**
- 部署完成后，访问分配的域名/绑定的自定义域名即可。

### 2. 使用方法
- **前端网页测试查询**：直接访问首页（`/`），输入域名、选择类型，可展开高级选项填入自定义参数后查询。

- **CF 静态映射范围（默认强制优选 IP）**：仅 Cloudflare 自有域名（cloudflare.com/cloudflare-dns.com/pages.dev/workers.dev）。其他网站默认保留真实 A/AAAA 与 HTTPS 记录；仅在 `best=true` 时尝试动态归属探测与优选增强。
  - **Meta 系**：facebook.com/instagram.com/whatsapp.com/messenger.com/fb.com/meta.com（优先查询域名自己的 ECH 配置，必要时保留短 TTL 的兼容配置）
  - **增强规则（enhance=rule/full）**：Google 系（google.com/youtube.com/googleapis.com/gstatic.com 等 → Google IPv6 直连）、Meta 全家桶 IPv6、Medium、Pinterest
  - **best=true 全局跟随**：任意 CF 托管的网站（自动归属探测）都使用优选 IP + ECH 注入
- **优选 IP 订阅**：`https://你的域名/sub.txt`；将订阅用于 `sub=ip-https://...` 时必须先为 Worker 配置 `DOH_ALLOWED_SUB_HOSTS`，默认不允许从外部 URL 下载。
- **DOH地址(完整参数示例)**：  
  ```
   "https://your-domain.pages.dev/ech?sub=ip-https://bestcf.pages.dev/gslege/Cfxyz.txt&best=true"
  ```
- **配置 DoH 客户端**：  
  -- 将支持ECH的浏览器如Chrome/Firefox 的安全DNS设置为 DoH 地址设置：`https://你的域名/ech`，并可通过 URL 参数传递自定义内容。

  
  -- 使用代理工具：将需要直连的CF站点的域名解析服务器doh设置为`https://你的域名/ech`，并可通过请求头或 URL 参数传递自定义内容。
---
## 注意事项
- **限额**：Cloudflare Workers 的免费配额、子请求额度和缓存能力可能变化，请以当前 Cloudflare 官方文档及账号限制为准；不应将应用层缓存当作抵御大量滥用查询的手段。
- **ECH 有效性**：Cloudflare 的 ECH 从指定域名动态获取，可自定义 `ech` 参数。Meta 优先使用目标域名发布的 ECH；仅已知 Meta 域名允许使用原有兼容配置，TTL 最高 30 秒，并定期重查。`echSource` 为 `dns` 或 `legacy-meta`，后者不保证所有站点长期可用。可使用 `go run scripts/probe-meta-ech.go` 或 GitHub Actions 的 `Meta ECH verification` 进行证书验证与实际 TLS ECH 握手探测，探测不会自动改写生产配置。
- **隐私与安全**：当前上游包含阿里 DNS、DNSPod 和 Cloudflare；国内域名分流至阿里 DNS/DNSPod。客户端 IP 仅转换为 IPv4 /24 或 IPv6 /56 网段后作为 ECS 发送给上游；无法获取有效地址时不发送 ECS。网段仍会透露大致网络位置，因此需考虑隐私需求。可调整 `_worker.js` 顶部的上游配置。
  
## 项目特性

- ✅ **DoH 服务**  
  提供 `/ech`（注入 ECH和enhance mode）和 `/doh`（纯净转发）两个标准 DoH 端点，支持 GET/POST。
- ✅ **多上游竞速**  
  阿里 DNS、DNSPod、Cloudflare 上游根据本地近期延迟与失败记录自适应排序，优先请求表现较好的上游；100ms 后仍未得到有效答案时启动下一家，遇到失败或不完整响应立即切换。国内域名继续使用阿里 / DNSPod，所有配置的上游仍保留作为回退。
- ✅ **长时间运行的规则刷新**  
  国内域名列表和 hosts 规则按有效期刷新，刷新失败保留最近可用数据并短期重试；CDN 归属探测按真实 DNS TTL 与 ECS 网段隔离，避免将混合 IP 记录误判成单一 CDN。
- ✅ **边缘节点本地缓存**  
  使用 Cloudflare Cache API 缓存可复用的正向上游 DNS 结果，按上游组、ECS 网段及 ECH 选择策略隔离；遵守记录 TTL，命中时扣减缓存年龄，不缓存零 TTL 或负应答。缓存仅在所在边缘数据中心复用，不是全球自动复制。
- ✅ **ECS就近解析**  
  默认获取 DoH 客户端 IP（可用 `clientIp` 自定义），向上游仅发送规范化的 IPv4 /24 或 IPv6 /56 网段；按网段及上游策略隔离缓存。ECS 可能帮助就近解析，但不保证最佳连接性能。


### Google / X 原生直连诊断

- 查询台新增 **Google 直连诊断** 与 **X 直连诊断**，可同时检查 A、AAAA、HTTPS 记录。
- 浏览器安全 DNS 可使用 `https://你的域名/ech?enhance=direct`；该模式仅针对 Google/X 及列出的相关资源域名，优先通过 Cloudflare DNS 返回真实记录，不使用随机 IPv6、hosts 替换或通用 CDN 优选。首选上游失败时回退至既有国际上游；其他域名仍按默认/显式高级策略解析。
- `enhance=rule` 继续保留原 Google IPv6 增强策略，便于对照；`/doh` 保持纯转发。原生直连模式不会为不支持 ECH 的目标伪造 ECH 配置。
- DNS 成功不等于目标可达。关闭系统代理、VPN/TUN 后再测试；不要关闭 TLS 证书验证。Google 可对照 IPv4 和 IPv6，X 若没有 AAAA 则不强制 IPv6。

Windows PowerShell（测试实际直连 HTTPS，绕过显式代理；不自动关闭 TUN/VPN）：

```powershell
$dns = 'https://你的域名/ech?enhance=direct'
curl.exe --noproxy "*" --doh-url "$dns" -6 --connect-timeout 8 --max-time 20 -I https://www.google.com/
curl.exe --noproxy "*" --doh-url "$dns" -4 --connect-timeout 8 --max-time 20 -I https://x.com/
```

HTTP 200/3xx 表示收到网站响应；403/429 也表示 TLS/HTTP 已到达服务，但不代表网页可正常使用。若超时或 TLS 失败，检查本机 IPv6 路由、代理状态及运营商网络。curl 的实际 ECH 能力取决于其 TLS 后端，此命令不保证使用 ECH。


### 本机实测优选（Google / X）

在 Android 的 Termux 或 Windows 的 Python 3 中运行 `scripts/direct-probe.py`。不需要额外 Python 库，不修改网络设置，不上传报告。先关闭代理、VPN、TUN，再运行：

```bash
python direct-probe.py --host www.google.com --host x.com --legacy
```

默认候选来自真实 DNS；`--legacy` 额外检查原 Google IPv6 规则返回的一部分候选。脚本对每个真实地址直接建立 TCP 443、验证 TLS 证书和目标 SNI，再请求 HTTP 首页。仅 2xx/3xx 候选可进入本机配置，按总耗时排列，每域名每地址族最多保留三个；403/429 等仅表明收到 HTTP 响应，不算可用地址。默认不探测任意域名，仅固定的 Google/X 及其相关资源域名。可不指定 --host 检测完整列表。

如果有通过项，脚本会打印 `/ech?enhance=direct&pins=...` 的专属 URL，并在本地写入 `direct-probe-result.json`。若所有地址失败，不生成虚假的成功配置。报告不会自动上传。将输出 URL 填入浏览器安全 DNS；高级设置中的 pins 也支持手动输入。同一 URL 仅指定的域名和地址族使用指定 IP，TTL 30 秒；其他域名及地址族使用原生 DNS，HTTPS 保留原生记录。浏览器可能根据原生 HTTPS hints 选择其他地址。DNS 记录到期不代表自动撤销 URL 中的 pin；网络变化后重新运行并更新 URL。多个候选依赖客户端自己的地址重试机制，服务端不声称能监测客户端网络。脚本使用普通 TLS（不证明 ECH 握手），且不绕过 VPN/TUN 路由。


若关闭代理后连 Doh-ECH 查询接口本身都失败，请先在代理/VPN/TUN 开启、Termux 可访问 DoH 服务时下载候选，再关闭代理实测：

```bash
python direct-probe.py --host www.google.com --host x.com --legacy --prepare
# 关闭代理、VPN/TUN 后：
python direct-probe.py --offline
```

`--prepare` 仅保存候选 IP 到 `direct-candidates.json`，不做连通性判断；`--offline` 直接使用其中的 IP 建立连接，不再请求 DNS 服务。无候选时不会覆盖已有文件。候选来自下载时的网络和 DNS 视角，仍须本机测试，不保证覆盖所有可用地址。

候选获取遇到 HTTP 403、超时或其他 DNS API 失败时，新版脚本自动尝试 Google Public DNS 和 Cloudflare DNS 的 HTTPS JSON 接口获取原生候选，并校验问题域名和记录类型。备用 DNS 不生成旧增强规则地址；若 `--legacy` 获取失败，原生候选仍可继续离线测试。此回退不会修改 Worker 安全规则，也不会证明备用解析器在关闭代理后可访问。


### 独立原生地址池与 HTTP/3 专项

开启代理，仅下载候选（保留旧报告与旧候选文件，另存一份）：

```bash
python direct-probe.py --host www.google.com --host x.com --prepare --expanded --candidates direct-native.json
```

`--expanded` 独立查询 Google Public DNS 和 Cloudflare DNS 的 A/AAAA/HTTPS 记录，合并去重真实地址，保存原始 HTTPS 记录及错误；不调用项目自身的增强规则，不生成随机 IPv6，不上传报告。原生 HTTPS 记录仅用于查看服务宣告，包含 ech 参数也不能证明 ECH 握手已被接受。

关闭代理、VPN/TUN 后：

```bash
python direct-probe.py --offline --candidates direct-native.json --timeout 8
python direct-probe.py --http3-probe --candidates direct-native.json --timeout 12
```

HTTP/3 专项需要能启动且 `curl --version` 的 Features 行包含 HTTP3 的 curl。它以 `--http3-only`、指定 IP 和真实 TLS 主机名进行 QUIC/UDP 443 连接，不降级至 TCP，不关闭证书验证，不跟随重定向；验证实际 HTTP 版本、IP、证书及响应码。每域名每地址族最多两个候选；HTTP/3 专项结果单独写入 `direct-http3-result.json`，不自动生成 DNS pins。客户端不具备 HTTP/3 能力时明确跳过网络测试。仅 HTTP/3 成功不能保证浏览器后续会选择该协议，也不能证明整个网站可用。
