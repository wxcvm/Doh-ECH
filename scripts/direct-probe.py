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

def read_dns_json(url):
    request = urllib.request.Request(url, headers={"Accept": "application/dns-json",
                                                    "User-Agent": "Doh-ECH-Direct-Probe/1.1"})
    with OPENER.open(request, timeout=10) as response:
        return json.load(response)

def valid_addresses(values, kind):
    result = []
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_global and ip.version == (6 if kind == "AAAA" else 4):
                result.append(str(ip))
        except ValueError:
            pass
    return list(dict.fromkeys(result))

def candidates(base, host, kind, profile):
    query = urllib.parse.urlencode({"domain": host, "type": kind, "enhance": profile})
    errors = []
    try:
        data = read_dns_json(base.rstrip("/") + "/api/query?" + query)
        if data.get("rcode", 0) != 0 or data.get("error"):
            raise RuntimeError(str(data.get("error") or "DNS RCODE " + str(data["rcode"])))
        if not isinstance(data.get("answers"), list):
            raise ValueError("invalid Doh-ECH response")
        return valid_addresses(data["answers"], kind)
    except (OSError, ValueError, RuntimeError) as error:
        errors.append("Doh-ECH: " + str(error))
    # Public recursive resolvers supply native DNS only; never label their answers as legacy.
    if profile != "direct":
        raise RuntimeError("; ".join(errors))
    dns_type = 28 if kind == "AAAA" else 1
    query = urllib.parse.urlencode({"name": host, "type": kind})
    for label, endpoint in (("Google Public DNS", "https://dns.google/resolve"),
                            ("Cloudflare DNS", "https://cloudflare-dns.com/dns-query")):
        try:
            data = read_dns_json(endpoint + "?" + query)
            question = data.get("Question")
            if (not isinstance(question, list) or len(question) != 1
                    or question[0].get("name", "").rstrip(".").lower() != host.lower()
                    or question[0].get("type") != dns_type):
                raise ValueError("DNS question mismatch")
            if data.get("Status") != 0:
                raise RuntimeError("DNS RCODE " + str(data.get("Status")))
            answers = valid_addresses([r["data"] for r in data.get("Answer", [])
                                       if r.get("type") == dns_type and "data" in r], kind)
            print(f"DNS fallback {host} {kind}: {label} (Doh-ECH unavailable)", flush=True)
            return answers
        except (OSError, ValueError, RuntimeError, TypeError, AttributeError) as error:
            errors.append(label + ": " + str(error))
    raise RuntimeError("; ".join(errors))


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
                print(f"DNS {host} legacy AAAA: unavailable ({error}); native candidates retained", flush=True)
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

def tls_check(host, ip, mode, timeout):
    # Diagnostic-only: no HTTP request and no pin generated by these checks.
    # The no-SNI control validates the certificate chain but not the hostname.
    # It must never be used to authenticate the requested site.
    context = ssl.create_default_context()
    if mode == "TLS1.2":
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    if mode == "TLS1.3-no-SNI":
        context.check_hostname = False
    result = {"host": host, "ip": ip, "mode": mode, "stage": "TCP", "ok": False}
    start = time.monotonic()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443))
            result["tcp_ms"] = round((time.monotonic()-start)*1000)
            result["stage"] = "TLS"
            with context.wrap_socket(raw, server_hostname=None if mode == "TLS1.3-no-SNI" else host) as tls:
                result.update(stage="TLS response", ok=True, version=tls.version(),
                              tls_ms=round((time.monotonic()-start)*1000),
                              hostname_verified=mode != "TLS1.3-no-SNI")
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    return result

def diagnose_tls(path, hosts, timeout):
    with open(path, encoding="utf-8") as source:
        report = json.load(source)
    selected = {}
    for item in report.get("results", []):
        if item.get("host") not in hosts or item.get("stage") != "TLS" or item.get("ok"):
            continue
        ip = ipaddress.ip_address(item["ip"])
        if ip.is_global:
            selected.setdefault(item["host"], []).append(item)
    jobs = []
    for host, items in selected.items():
        seen = set()
        for item in sorted(items, key=lambda x: x.get("tcp_ms", 10**9)):
            ip = str(ipaddress.ip_address(item["ip"]))
            if ip in seen:
                continue
            seen.add(ip)
            jobs.extend((host, ip, mode, timeout) for mode in ("TLS1.2", "TLS1.3", "TLS1.3-no-SNI"))
            if len(seen) == 2:
                break
    print("TLS diagnostic only: no HTTP requests, no DNS, no pins. No-SNI control is not hostname authenticated.")
    if not jobs:
        print("No previous TLS failures with TCP success. Run --offline first.")
        return
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        # Run the three modes in sequence per IP to avoid overlapping the same connection.
        def compare(group):
            return [tls_check(*job) for job in group]
        for group in pool.map(compare, [jobs[i:i+3] for i in range(0, len(jobs), 3)]):
            for item in group:
                results.append(item)
                print(f"{item['host']} {item['ip']} {item['mode']} {item['stage']} "
                      f"{item.get('version', item.get('error', ''))} "
                      f"{item.get('tls_ms', item.get('tcp_ms', ''))}ms", flush=True)
    with open("direct-tls-diagnosis.json", "w", encoding="utf-8") as output:
        json.dump(results, output, indent=2)
    print("Local report: direct-tls-diagnosis.json (no address profile generated)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT, help="HTTPS Doh-ECH origin")
    parser.add_argument("--host", action="append", choices=HOSTS, help="repeat to select hosts")
    parser.add_argument("--legacy", action="store_true", help="also test up to 8 legacy Google IPv6 candidates; no automatic trust")
    parser.add_argument("--timeout", type=float, default=5.0)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="download candidates only, proxy may be on")
    modes.add_argument("--offline", action="store_true", help="test saved literal IPs without contacting the DNS service")
    modes.add_argument("--tls-diagnose", action="store_true", help="compare TLS versions/SNI on prior TCP-success TLS failures")
    parser.add_argument("--report", default="direct-probe-result.json", help="input report for TLS diagnosis")
    parser.add_argument("--candidates", default="direct-candidates.json", help="candidate file path")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    url = urllib.parse.urlsplit(base)
    if url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment or url.username:
        parser.error("--base must be an HTTPS origin, without a path or query")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be 1..30 seconds")
    hosts = args.host or HOSTS
    if args.tls_diagnose:
        try:
            diagnose_tls(args.report, hosts, args.timeout)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.exit(1, f"Cannot diagnose TLS: {error}\\n")
        return
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
