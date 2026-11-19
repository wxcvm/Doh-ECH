import importlib.util
import io
import json
import sys
import pathlib
import struct
import unittest
from unittest.mock import patch
from email.message import Message

spec = importlib.util.spec_from_file_location("probe", pathlib.Path(__file__).resolve().parents[1] / "scripts/balanced-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Reply(io.BytesIO):
    def __init__(self, data, content_type="application/dns-message"):
        super().__init__(data)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["X-Cache"] = "INTERNATIONAL_HIT"


class ProbeTests(unittest.TestCase):
    def test_custom_hosts_without_network(self):
        argv = ["probe", "--url", "https://example.com/ech", "--rounds", "1",
                "--hosts", "www.jd.com, www.cloudflare.com."]
        with patch.object(sys, "argv", argv), \
             patch.object(probe, "dns_probe", return_value={"ms": 1, "rcode_low4": 0}) as dns, \
             patch.object(probe, "https_probe", return_value={"tls_ms": 1}), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            probe.main()
        rows = json.loads(out.getvalue())["samples"]
        self.assertEqual({r["host"] for r in rows}, {"www.jd.com", "www.cloudflare.com"})
        self.assertEqual(dns.call_count, 6)

    def test_interleaved_baseline_preserves_target_address_and_default(self):
        argv = ["probe", "--url", "https://target.example/ech", "--baseline-url",
                "https://baseline.example/dns-query", "--hosts", "www.jd.com",
                "--rounds", "2", "--dns-only", "--doh-connect"]
        def fake_dns(url, host, kind, timeout, method):
            return {"ms": 1, "rcode_low4": 0,
                    "addresses": ["203.0.113.1"] if url.startswith("https://target") and kind == 1 else
                                 ["198.51.100.2"] if kind == 1 else []}
        with patch.object(sys, "argv", argv), \
             patch.object(probe, "dns_probe", side_effect=fake_dns) as dns, \\
             patch.object(probe, "https_probe", side_effect=AssertionError("website probe called")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            probe.main()
        rows = json.loads(out.getvalue())["samples"]
        self.assertEqual(dns.call_count, 12)
        self.assertEqual([r["endpoint"] for r in rows],
                         ["target", "baseline"] * 6)
        self.assertEqual({r["host"] for r in rows}, {"www.jd.com"})

    def test_reject_non_https_baseline(self):
        with patch.object(sys, "argv", ["probe", "--url", "https://example.com/ech",
                                        "--baseline-url", "http://insecure.example/dns-query"]):
            with self.assertRaises(SystemExit) as error:
                probe.main()
        self.assertEqual(error.exception.code, 2)

    def test_dns_only_skips_website_connections(self):
        argv = ["probe", "--url", "https://example.com/ech", "--rounds", "2",
                "--hosts", "www.jd.com", "--dns-only", "--doh-connect"]
        with patch.object(sys, "argv", argv), \
             patch.object(probe, "dns_probe", return_value={"ms": 1, "rcode_low4": 0}) as dns, \
             patch.object(probe, "https_probe", side_effect=AssertionError("website probe called")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            probe.main()
        rows = json.loads(out.getvalue())["samples"]
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(isinstance(row["type"], int) for row in rows))
        self.assertEqual(dns.call_count, 6)

    def test_reject_invalid_custom_host(self):
        with patch.object(sys, "argv", ["probe", "--url", "https://example.com/ech",
                                         "--hosts", "valid.example,invalid_domain"]):
            with self.assertRaises(SystemExit) as error:
                probe.main()
        self.assertEqual(error.exception.code, 2)

    def test_query(self):
        for kind in (1, 28, 65):
            packet = probe.query("example.com", kind)
            self.assertEqual(struct.unpack("!5H", packet[2:12]), (256, 1, 0, 0, 0))
            self.assertEqual(packet[12:], b"\x07example\x03com\x00" + struct.pack("!HH", kind, 1))

    def test_explicit_user_agent_for_get_and_post(self):
        def respond(req, timeout):
            self.assertEqual(req.get_header("User-agent"), "Doh-ECH-DoH-Probe/1.0")
            if req.data is None:
                encoded = probe.urllib.parse.parse_qs(probe.urllib.parse.urlsplit(req.full_url).query)["dns"][0]
                packet = probe.base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            else:
                packet = req.data
            return Reply(packet[:2] + struct.pack("!5H", 0x8180, 1, 0, 0, 0) + packet[12:])

        with patch.object(probe.urllib.request, "urlopen", side_effect=respond):
            for method in ("POST", "GET"):
                result = probe.dns_probe("https://example.com/ech?enhance=balanced", "example.com", 1, 1, method)
                self.assertEqual(result["rcode_low4"], 0)

    def test_response(self):
        def respond(req, timeout):
            packet = req.data
            return Reply(packet[:2] + struct.pack("!5H", 0x8383, 1, 0, 0, 0) + packet[12:])
        with patch.object(probe.urllib.request, "urlopen", side_effect=respond):
            result = probe.dns_probe("https://example.com/ech", "example.com", 65, 1)
        self.assertEqual(result["rcode_low4"], 3)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["cache"], "INTERNATIONAL_HIT")

    def test_addresses(self):
        for kind, raw, expected in ((1, bytes([203, 0, 113, 7]), "203.0.113.7"),
                                    (28, bytes.fromhex("20010db8000000000000000000000001"), "2001:db8::1")):
            def respond(req, timeout):
                packet = req.data
                rr = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(raw)) + raw
                return Reply(packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:] + rr)
            with patch.object(probe.urllib.request, "urlopen", side_effect=respond):
                result = probe.dns_probe("https://example.com/ech", "example.com", kind, 1)
            self.assertEqual(result["addresses"], [expected])
        with self.assertRaises(ValueError):
            probe.answer_addresses(b"\xc0", 0, 1, 1)

    def test_invalid_response(self):
        for reply in (Reply(b"short"), Reply(b"short", "text/html")):
            with patch.object(probe.urllib.request, "urlopen", return_value=reply):
                result = probe.measure(probe.dns_probe, "https://example.com/ech", "example.com", 1, 1)
            self.assertIn("error", result)

    def test_timeout(self):
        with patch.object(probe.urllib.request, "urlopen", side_effect=TimeoutError("timeout")):
            self.assertEqual(probe.measure(probe.dns_probe, "https://example.com/ech", "example.com", 1, 1), {"error": "timeout"})


# Include global analytics regression tests in the existing benchmark CI job.
_summary_spec = importlib.util.spec_from_file_location(
    "global_summary_tests", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "test-global-dns-summary.py")
_summary_tests = importlib.util.module_from_spec(_summary_spec)
_summary_spec.loader.exec_module(_summary_tests)
SummaryTests = _summary_tests.SummaryTests

if __name__ == "__main__":
    unittest.main()
