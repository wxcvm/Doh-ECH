"""Client-side balanced DoH benchmark; Python 3 standard library only."""
import argparse
import json
import secrets
import socket
import ssl
import struct
import time
import urllib.request

HOSTS = ("www.baidu.com", "www.bilibili.com", "www.jd.com",
         "www.google.com", "www.youtube.com", "www.cloudflare.com")


def query(host, kind):
    ident = secrets.randbelow(65536)
    name = b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in host.split(".")) + b"\0"
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", kind, 1)


def dns_probe(url, host, kind, timeout):
    packet = query(host, kind)
    req = urllib.request.Request(url, data=packet, headers={
        "Content-Type": "application/dns-message", "Accept": "application/dns-message"})
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
            "rcode_low4": flags & 15, "truncated": bool(flags & 0x200), "answers": an}


def https_probe(host, timeout):
    # System resolver and current network route; not attributed to the tested DoH.
    start = time.monotonic()
    with socket.create_connection((host, 443), timeout=timeout) as raw:
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
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()
    if not args.url.startswith("https://") or args.rounds < 1 or args.timeout <= 0:
        parser.error("HTTPS URL, positive rounds and timeout required")
    rows = []
    for host in HOSTS:
        for kind in (1, 28, 65):
            for i in range(args.rounds):
                rows.append({"host": host, "type": kind, "round": i+1,
                             **measure(dns_probe, args.url, host, kind, args.timeout)})
        rows.append({"host": host, "type": "system_https", **measure(https_probe, host, args.timeout)})
    print(json.dumps({"note": "First query is not guaranteed cold; X-Cache identifies observed hits. HTTPS uses system DNS, not necessarily tested DoH. No ECH verification.", "samples": rows}, indent=2))


if __name__ == "__main__":
    main()
