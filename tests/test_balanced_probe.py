import importlib.util
import io
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
    def test_query(self):
        for kind in (1, 28, 65):
            packet = probe.query("example.com", kind)
            self.assertEqual(struct.unpack("!5H", packet[2:12]), (256, 1, 0, 0, 0))
            self.assertEqual(packet[12:], b"\x07example\x03com\x00" + struct.pack("!HH", kind, 1))

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
