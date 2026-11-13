#!/usr/bin/env python3
"""Local DNS / TCP / certificate-verified TLS / HTTP diagnostics.
Run on the actual client network, with proxy, TUN and VPN disabled.
No third-party packages, no system settings changes, no report uploads.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request

HOSTS = ["www.google.com", "accounts.google.com", "www.gstatic.com",
         "x.com", "api.x.com", "pbs.twimg.com", "abs.twimg.com"]
DEFAULT = "https://dohech.dpdns.org"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CONTEXT = ssl.create_default_context()

def candidates(base, host, kind, profile):
    query = urllib.parse.urlencode({"domain": host, "type": kind, "enhance": profile})
    with OPENER.open(base.rstrip("/") + "/api/query?" + query, timeout=10) as response:
        data = json.load(response)
    if data.get("rcode", 0) != 0 or data.get("error"):
        raise RuntimeError(str(data.get("error") or "DNS RCODE " + str(data["rcode"])))
    result = []
    for value in data.get("answers", []):
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_global and ip.version == (6 if kind == "AAAA" else 4):
                result.append(str(ip))
        except ValueError:
            pass
    return list(dict.fromkeys(result))

def probe(host, ip, source, timeout):
    result = {"host": host, "ip": ip, "source": source, "stage": "TCP",
              "ok": False}
    start = time.monotonic()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443))
            result["tcp_ms"] = round((time.monotonic() - start) * 1000)
            result["stage"] = "TLS"
            with CONTEXT.wrap_socket(raw, server_hostname=host) as tls:
                result["tls_ms"] = round((time.monotonic() - start) * 1000)
                result["stage"] = "HTTP"
                request = ("GET / HTTP/1.1\r\nHost: " + host +
                           "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                tls.sendall(request.encode("ascii"))
                with tls.makefile("rb") as stream:
                    line = stream.readline(4096).decode("ascii", errors="replace")
                parts = line.split()
                if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                    raise ValueError("invalid HTTP status line")
                status = int(parts[1])
                result.update(http_status=status, total_ms=round((time.monotonic()-start)*1000),
                              ok=200 <= status < 400)
                result["stage"] = "HTTP response"
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    return result

def select_pins(results):
    # Only actual certificate-verified HTTP success; never treat a timeout, 403 or
    # an IP that worked on a different hostname as a usable address.
    groups = {}
    for item in results:
        if item["ok"]:
            key = (item["host"], ":" in item["ip"])
            groups.setdefault(key, []).append(item)
    hosts = {}
    for (host, _family), items in sorted(groups.items()):
        ranked = sorted(items, key=lambda x: (x["total_ms"], x["ip"]))
        hosts.setdefault(host, []).extend(list(dict.fromkeys(x["ip"] for x in ranked))[:3])
    return ";".join(host + "=" + ",".join(ips) for host, ips in hosts.items())

def collect_jobs(base, hosts, legacy, timeout):
    jobs = []
    dns_errors = []
    for host in hosts:
        for kind in ("A", "AAAA"):
            try:
                ips = candidates(base, host, kind, "direct")
                print(f"DNS {host} {kind}: {', '.join(ips) or 'no records'}", flush=True)
                jobs.extend((host, ip, "native", timeout) for ip in ips[:8])
            except (OSError, ValueError, RuntimeError) as error:
                dns_errors.append({"host": host, "type": kind, "error": str(error)})
                print(f"DNS {host} {kind}: FAILED {error}", flush=True)
        if legacy and host.endswith(".google.com"):
            try:
                native = {job[1] for job in jobs if job[0] == host}
                ips = candidates(base, host, "AAAA", "rule")
                jobs.extend((host, ip, "legacy-candidate", timeout)
                            for ip in ips[:8] if ip not in native)
            except (OSError, ValueError, RuntimeError) as error:
                dns_errors.append({"host": host, "type": "legacy AAAA", "error": str(error)})
    return jobs, dns_errors

def save_candidates(path, base, jobs, dns_errors):
    # Store literal addresses only; downloading candidates is not a connectivity test.
    with open(path, "w", encoding="utf-8") as output:
        json.dump({"base": base, "jobs": [list(j[:3]) for j in jobs],
                   "dns_errors": dns_errors}, output, indent=2)
    print(f"Saved {len(jobs)} candidates to {path}. Disable proxy/VPN/TUN before --offline.")

def load_candidates(path, base, hosts, timeout):
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
    if data.get("base") != base:
        raise ValueError("Candidate file belongs to a different DoH origin")
    jobs = []
    for host, value, origin in data["jobs"]:
        ip = ipaddress.ip_address(value)
        if host in hosts and ip.is_global and origin in ("native", "legacy-candidate"):
            jobs.append((host, str(ip), origin, timeout))
    return list(dict.fromkeys(jobs)), data.get("dns_errors", [])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT, help="HTTPS Doh-ECH origin")
    parser.add_argument("--host", action="append", choices=HOSTS, help="repeat to select hosts")
    parser.add_argument("--legacy", action="store_true", help="also test up to 8 legacy Google IPv6 candidates; no automatic trust")
    parser.add_argument("--timeout", type=float, default=5.0)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="download candidates only, proxy may be on")
    modes.add_argument("--offline", action="store_true", help="test saved literal IPs without contacting the DNS service")
    parser.add_argument("--candidates", default="direct-candidates.json", help="candidate file path")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    url = urllib.parse.urlsplit(base)
    if url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment or url.username:
        parser.error("--base must be an HTTPS origin, without a path or query")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be 1..30 seconds")
    hosts = args.host or HOSTS
    if args.prepare:
        jobs, dns_errors = collect_jobs(base, hosts, args.legacy, args.timeout)
        if not jobs:
            parser.exit(1, "No candidates downloaded; existing candidate file unchanged.\n")
        save_candidates(args.candidates, base, jobs, dns_errors)
        return
    print("Disable proxy, VPN and TUN before running. Direct sockets bypass explicit HTTP proxies, not VPN routing.")
    if args.offline:
        try:
            jobs, dns_errors = load_candidates(args.candidates, base, hosts, args.timeout)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.exit(1, f"Cannot load candidate file: {error}. Run --prepare first.\n")
        print(f"Loaded {len(jobs)} saved candidates; no DNS service request will be made.")
    else:
        jobs, dns_errors = collect_jobs(base, hosts, args.legacy, args.timeout)
    if not jobs:
        print("No candidates to test. This is a DNS acquisition failure, not a target connectivity result.")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(probe, *job) for job in jobs]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            results.append(item)
            print(f"{item['host']} {item['ip']} {item['stage']} "
                  f"{item.get('http_status', item.get('error', ''))} "
                  f"{item.get('total_ms', item.get('tls_ms', item.get('tcp_ms', '')))}ms", flush=True)
    pins = select_pins(results)
    endpoint = base + "/ech?" + urllib.parse.urlencode({"enhance": "direct", **({"pins": pins} if pins else {})})
    report = {"dns_errors": dns_errors, "results": results, "pins": pins,
              "endpoint": endpoint if pins else None}
    with open("direct-probe-result.json", "w", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
    if pins:
        print("\nVerified address profile (valid for this network; retest after network changes):\n" + endpoint)
        print("HTTP success is not proof of full website functionality. DNS HTTPS hints may also affect browser routing.")
    else:
        print("\nNo verified addresses. Do not switch DNS to an unverified candidate.")
    print("Local report: direct-probe-result.json")

if __name__ == "__main__":
    main()
