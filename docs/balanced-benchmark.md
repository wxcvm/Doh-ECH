# Balanced real-network benchmark

This is an **opt-in**, zero-dependency Node.js probe. It makes real external requests and does not change device settings, DNS settings, or deployed Worker configuration.

```sh
node scripts/benchmark-balanced.mjs --resolver 'https://YOUR-WORKER/ech?enhance=balanced&cnEcs=auto' --domains www.taobao.com,www.bilibili.com,www.google.com,cloudflare.com --samples 5 > balanced-results.json
```

Run the same command from mainland China and from an overseas network, recording the date, ISP/region and whether a proxy/VPN is active. Do not publish identifying client IPs. Compare results for domestic and international names separately. Use the same domain set and sample count for baseline measurements.

- **DNS**: POST DNS-wire A queries to the specified DoH URL, measure complete response time, HTTP validity, DNS RCODE, answer count, `X-Cache`, and `X-DNS-Route`. `dnsFirstObserved` is *not* guaranteed cold because upstream/edge caches may already be warm; later samples are only *potential* warm hits. Check `X-Cache` before labeling a cache hit.
- **TLS**: independently connect to each hostname using the system resolver and measure verified TLS handshake time. This does **not** prove that the DoH answer was used.
- **TTFB**: independently request HTTPS / using the system resolver and measure time until response headers. This does **not** isolate DNS performance or prove ECH was negotiated.
- Errors are included in JSON rather than silently dropped. No sample values are fabricated.

This is an initial reproducible field probe, **not** an end-to-end ECH/AdGuard validation. For genuine end-to-end comparisons, configure a controlled test client to use the target DoH endpoint and separately inspect the HTTPS/SVCB answer, negotiated TLS/ECH and AdGuard query log. Do not label this script's TLS or TTFB results as DoH-routed.
