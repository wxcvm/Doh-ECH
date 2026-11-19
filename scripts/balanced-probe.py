"""Client-side balanced DoH benchmark; Python 3 standard library only."""
import argparse
import base64
import json
import secrets
import socket
import ssl
import struct
import time
import urllib.request
import urllib.error
import urllib.parse

HOSTS = ("www.baidu.com", "www.bilibili.com", "www.jd.com",
         "www.google.com", "www.youtube.com", "www.cloudflare.com")


def query(host, kind):
    ident = secrets.randbelow(65536)
    name = b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in host.split(".")) + b"\0"
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", kind, 1)


def answer_addresses(data, offset, count, kind):
    addresses = []
    for _ in range(count):
        while True:
            if offset >= len(data):
                raise ValueError("truncated DNS name")
            size = data[offset]
            offset += 1
            if size & 0xc0 == 0xc0:
                offset += 1
                break
            if size == 0:
                break
            if size > 63:
                raise ValueError("invalid DNS label")
            offset += size
        if offset + 10 > len(data):
            raise ValueError("truncated DNS record")
        rrtype, rrclass, _, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + length > len(data):
            raise ValueError("truncated DNS RDATA")
        if rrclass == 1 and rrtype == kind and kind in (1, 28):
            if length != (4 if kind == 1 else 16):
                raise ValueError("invalid address length")
            addresses.append(socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                             data[offset:offset+length]))
        offset += length
    return addresses


def dns_probe(url, host, kind, timeout, method="POST"):
    packet = query(host, kind)
    # workers.dev rejects some default library user agents before Worker execution.
    headers = {"Accept": "application/dns-message", "User-Agent": "Doh-ECH-DoH-Probe/1.0"}
    if method == "GET":
        parts = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        params = [(k, v) for k, v in params if k != "dns"]
        params.append(("dns", base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")))
        url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(params)))
        req = urllib.request.Request(url, headers=headers)
    else:
        headers["Content-Type"] = "application/dns-message"
        req = urllib.request.Request(url, data=packet, headers=headers)
    start = time.monotonic()
    with urllib.request.urlopen(req, timeout=timeout) as response:
        data = response.read(65536)
        cache = response.headers.get("X-Cache")
        if response.headers.get_content_type() != "application/dns-message":
            raise ValueError("unexpected content type")
    if len(data) < 12 or data[:2] != packet[:2]:
        raise ValueError("invalid DNS response")
    _, flags, qd, an, _, _ = struct.unpack("!6H", data[:12])
    if not flags & 0x8000 or qd != 1 or data[12:len(packet)] != packet[12:]:
        raise ValueError("DNS question mismatch")
    return {"ms": round((time.monotonic()-start)*1000, 2), "cache": cache,
            "rcode_low4": flags & 15, "truncated": bool(flags & 0x200), "answers": an,
            "addresses": answer_addresses(data, len(packet), an, kind) if not flags & 0x20f else []}


def https_probe(host, timeout, address=None):
    # System resolver and current network route; not attributed to the tested DoH.
    start = time.monotonic()
    with socket.create_connection((address or host, 443), timeout=timeout) as raw:
        connected = time.monotonic()
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            secured = time.monotonic()
            tls.sendall(("GET / HTTP/1.1\r\nHost: " + host +
                         "\r\nConnection: close\r\n\r\n").encode("ascii"))
            first = tls.recv(1)
            received = time.monotonic()
            if not first:
                raise ValueError("empty HTTP response")
            return {"resolve_connect_ms": round((connected-start)*1000, 2),
                    "tls_ms": round((secured-connected)*1000, 2),
                    "ttfb_after_tls_ms": round((received-secured)*1000, 2),
                    "total_first_byte_ms": round((received-start)*1000, 2),
                    "peer": tls.getpeername()[0]}


def measure(fn, *args):
    try:
        return fn(*args)
    except urllib.error.HTTPError as exc:
        # Keep only diagnostic response headers; never record credentials or cookies.
        return {"error": str(exc), "http_status": exc.code,
                "response_headers": {k: exc.headers.get(k) for k in
                                     ("Server", "CF-Ray", "CF-Mitigated", "Content-Type")
                                     if exc.headers.get(k) is not None}}
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST"), default="POST")
    parser.add_argument("--baseline-url", help="Optional second DoH endpoint for interleaved comparison (no device DNS changes)")
    parser.add_argument("--hosts", default=",".join(HOSTS), help="Comma-separated domains to probe; default is the six baseline sites")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--doh-connect", action="store_true", help="Also test TLS/TTFB using one returned address per family")
    parser.add_argument("--dns-only", action="store_true", help="Skip unrelated website TLS/TTFB probes when measuring DNS only")
    args = parser.parse_args()
    if (not args.url.startswith("https://") or
            (args.baseline_url is not None and not args.baseline_url.startswith("https://")) or
            args.rounds < 1 or args.timeout <= 0):
        parser.error("HTTPS URL, positive rounds and timeout required")
    hosts = [host.strip().lower().rstrip(".") for host in args.hosts.split(",")]
    if not hosts or any(not host or len(host) > 253 or any(
            not label or len(label) > 63 or not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label)
            for label in host.split(".")) for host in hosts):
        parser.error("--hosts requires comma-separated DNS hostnames")
    rows = []
    endpoints = (("target", args.url), ("baseline", args.baseline_url)) if args.baseline_url else (("target", args.url),)
    for host in hosts:
        addresses = {}
        for kind in (1, 28, 65):
            for i in range(args.rounds):
                for endpoint, endpoint_url in endpoints:
                    sample = measure(dns_probe, endpoint_url, host, kind, args.timeout, args.method)
                    row = {"host": host, "type": kind, "round": i+1, **sample}
                    if args.baseline_url:
                        row["endpoint"] = endpoint
                    rows.append(row)
                    if endpoint == "target" and sample.get("addresses"):
                        addresses.setdefault(kind, sample["addresses"][0])
        if args.doh_connect and not args.dns_only:
            for kind, address in addresses.items():
                rows.append({"host": host, "type": "doh_https", "family": kind, "address": address,
                             **measure(https_probe, host, args.timeout, address)})
        if not args.dns_only:
            rows.append({"host": host, "type": "system_https", **measure(https_probe, host, args.timeout)})
    print(json.dumps({"method": args.method, "note": "First query is not guaranteed cold; X-Cache identifies observed hits. Optional baseline queries are interleaved, not identical cache or network conditions, and may differ in ECS/ECH policy. HTTPS uses system DNS, not necessarily tested DoH. Optional doh_https connects to a target-returned address with original hostname/SNI and certificate verification; no ECH verification.", "samples": rows}, indent=2))


if __name__ == "__main__":
    main()
