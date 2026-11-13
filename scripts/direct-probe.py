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
import subprocess
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

PUBLIC_RESOLVERS = (("google", "https://dns.google/resolve"),
                    ("cloudflare", "https://cloudflare-dns.com/dns-query"))

def public_dns(endpoint, host, kind):
    dns_type = {"A": 1, "AAAA": 28, "HTTPS": 65}[kind]
    query = urllib.parse.urlencode({"name": host, "type": dns_type})
    data = read_dns_json(endpoint + "?" + query)
    question = data.get("Question")
    if (not isinstance(question, list) or len(question) != 1
            or question[0].get("name", "").rstrip(".").lower() != host.lower()
            or question[0].get("type") != dns_type):
        raise ValueError("DNS question mismatch")
    if data.get("Status") != 0:
        raise RuntimeError("DNS RCODE " + str(data.get("Status")))
    return [r["data"] for r in data.get("Answer", [])
            if r.get("type") == dns_type and "data" in r]

def collect_expanded(hosts, timeout):
    # Independent public DNS snapshots; no synthetic addresses or arbitrary prefixes.
    jobs, errors, https_records = [], [], []
    for host in hosts:
        for label, endpoint in PUBLIC_RESOLVERS:
            for kind in ("A", "AAAA", "HTTPS"):
                try:
                    values = public_dns(endpoint, host, kind)
                    if kind == "HTTPS":
                        https_records.append({"host": host, "resolver": label,
                                              "records": values})
                        print(f"DNS {label} {host} HTTPS: {values or 'no records'}", flush=True)
                    else:
                        ips = valid_addresses(values, kind)
                        print(f"DNS {label} {host} {kind}: {', '.join(ips) or 'no records'}", flush=True)
                        jobs.extend((host, ip, "native-" + label, timeout) for ip in ips[:8])
                except (OSError, ValueError, RuntimeError, TypeError, AttributeError) as error:
                    errors.append({"host": host, "type": kind, "resolver": label, "error": str(error)})
                    print(f"DNS {label} {host} {kind}: FAILED {error}", flush=True)
    # Preserve each IP's first source and test each host/IP only once.
    unique = {}
    for job in jobs:
        unique.setdefault(job[:2], job)
    return list(unique.values()), errors, https_records

def curl_http3_available():
    try:
        result = subprocess.run(["curl", "-q", "--version"], capture_output=True,
                                text=True, timeout=10)
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        features = next((line.split()[1:] for line in result.stdout.splitlines()
                         if line.startswith("Features:")), [])
        return "HTTP3" in features, "curl features: " + " ".join(features)
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error)

def http3_probe(host, ip, source, timeout):
    # Pin DNS to the chosen literal address, retain real SNI/certificate verification,
    # disable curl config/proxies and never fall back to TCP-based HTTP.
    address = "[" + ip + "]" if ":" in ip else ip
    command = ["curl", "-q", "--http3-only", "--noproxy", "*", "--proxy", "",
               "--resolve", host + ":443:" + address,
               "--connect-timeout", str(timeout), "--max-time", str(timeout),
               "--silent", "--show-error", "--output", "/dev/null",
               "--write-out", "%{http_code} %{http_version} %{remote_ip} %{ssl_verify_result}",
               "https://" + host + "/"]
    result = {"host": host, "ip": ip, "source": source, "protocol": "HTTP/3", "ok": False}
    start = time.monotonic()
    try:
        response = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 2)
        result["curl_exit"] = response.returncode
        fields = response.stdout.strip().split()
        if len(fields) == 4:
            status, version, remote, verify = fields
            result.update(http_status=int(status), http_version=version,
                          remote_ip=remote, ssl_verify_result=int(verify))
            result["ok"] = (response.returncode == 0 and version == "3"
                            and ipaddress.ip_address(remote) == ipaddress.ip_address(ip)
                            and verify == "0" and 200 <= int(status) < 400)
        if response.returncode != 0:
            result["error"] = response.stderr.strip()
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        result["error"] = str(error)
    result["total_ms"] = round((time.monotonic()-start)*1000)
    return result

def run_http3(jobs):
    available, details = curl_http3_available()
    if not available:
        print("HTTP/3 test unavailable: " + details)
        print("Requires a working curl build with HTTP3 in Features. No network test or address profile generated.")
        return False
    # Limit a diagnostic pass to two native candidates per host/address family.
    selected, counts = [], {}
    for job in jobs:
        host, ip, source, _ = job
        if not source.startswith("native"):
            continue
        key = (host, ":" in ip)
        if counts.get(key, 0) < 2:
            selected.append(job)
            counts[key] = counts.get(key, 0) + 1
    if not selected:
        print("No native candidates available for HTTP/3. Run --prepare --expanded first.")
        return False
    print("HTTP/3 only: UDP/QUIC, certificate verification, no TCP fallback. Disable VPN/TUN first.")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(lambda job: http3_probe(*job), selected):
            results.append(result)
            print(f"{result['host']} {result['ip']} HTTP/3 "
                  f"{result.get('http_status', 'no response')} "
                  f"{'VERIFIED' if result['ok'] else result.get('error', 'not verified')} "
                  f"{result['total_ms']}ms", flush=True)
    with open("direct-http3-result.json", "w", encoding="utf-8") as output:
        json.dump(results, output, indent=2)
    print("Local report: direct-http3-result.json (HTTP/3-specific; no DNS pins generated)")
    return True

def save_candidates(path, base, jobs, dns_errors, https_records=None):
    # Store literal addresses only; downloading candidates is not a connectivity test.
    with open(path, "w", encoding="utf-8") as output:
        json.dump({"base": base, "jobs": [list(j[:3]) for j in jobs],
                   "dns_errors": dns_errors, "https_records": https_records or []}, output, indent=2)
    print(f"Saved {len(jobs)} candidates to {path}. Disable proxy/VPN/TUN before --offline.")

def load_candidates(path, base, hosts, timeout):
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
    if data.get("base") != base:
        raise ValueError("Candidate file belongs to a different DoH origin")
    jobs = []
    for host, value, origin in data["jobs"]:
        ip = ipaddress.ip_address(value)
        if host in hosts and ip.is_global and origin in ("native", "legacy-candidate", "native-google", "native-cloudflare"):
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
    parser.add_argument("--expanded", action="store_true", help="prepare independent native DNS snapshots and HTTPS records from Google/Cloudflare")
    parser.add_argument("--legacy", action="store_true", help="also test up to 8 legacy Google IPv6 candidates; no automatic trust")
    parser.add_argument("--timeout", type=float, default=5.0)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="download candidates only, proxy may be on")
    modes.add_argument("--offline", action="store_true", help="test saved literal IPs without contacting the DNS service")
    modes.add_argument("--http3-probe", action="store_true", help="test native saved IPs using curl HTTP/3-only; no DNS requests")
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
    if args.expanded and not args.prepare:
        parser.error("--expanded requires --prepare")
    if args.expanded and args.legacy:
        parser.error("--expanded uses native records only; omit --legacy")
    if args.http3_probe:
        try:
            jobs, _ = load_candidates(args.candidates, base, hosts, args.timeout)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.exit(1, f"Cannot load candidate file: {error}. Run --prepare first.\\n")
        if not run_http3(jobs):
            parser.exit(1)
        return
    if args.tls_diagnose:
        try:
            diagnose_tls(args.report, hosts, args.timeout)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.exit(1, f"Cannot diagnose TLS: {error}\\n")
        return
    if args.prepare:
        https_records = None
        if args.expanded:
            jobs, dns_errors, https_records = collect_expanded(hosts, args.timeout)
        else:
            jobs, dns_errors = collect_jobs(base, hosts, args.legacy, args.timeout)
        if not jobs:
            parser.exit(1, "No candidates downloaded; existing candidate file unchanged.\n")
        save_candidates(args.candidates, base, jobs, dns_errors, https_records)
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
