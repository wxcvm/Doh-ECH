"""Offline regression for distinct TCP, TLS and HTTP timing phases."""
import importlib.util
import io
import pathlib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("direct_probe", pathlib.Path(__file__).with_name("direct-probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeSocket:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def settimeout(self, timeout):
        pass
    def connect(self, address):
        pass


class FakeTLS:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def sendall(self, request):
        pass
    def makefile(self, mode):
        return io.BytesIO(b"HTTP/1.1 200 OK\r\n")


class DirectProbeTimingTests(unittest.TestCase):
    def test_phase_durations_do_not_double_count_tcp(self):
        with mock.patch.object(probe.socket, "socket", return_value=FakeSocket()), \
             mock.patch.object(probe.CONTEXT, "wrap_socket", return_value=FakeTLS()), \
             mock.patch.object(probe.time, "monotonic", side_effect=[10.0, 10.02, 10.07, 10.11]):
            result = probe.probe("example.com", "93.184.215.14", "test", 3)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tcp_ms"], 20)
        self.assertEqual(result["tls_ms"], 50)
        self.assertEqual(result["ttfb_after_tls_ms"], 40)
        self.assertEqual(result["total_ms"], 110)


if __name__ == "__main__":
    unittest.main()
