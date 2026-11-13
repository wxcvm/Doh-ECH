import importlib.util
import pathlib
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import io
import json

spec=importlib.util.spec_from_file_location("direct_probe", pathlib.Path(__file__).resolve().parents[1]/"scripts/direct-probe.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class DirectProbeTests(unittest.TestCase):
    def test_candidates(self):
        payload={"rcode":0,"answers":["2001:4860:4860::8888","2001:4860:4860:0:0:0:0:8888","::1","invalid","8.8.8.8"]}
        response=io.StringIO(json.dumps(payload))
        with patch.object(mod.OPENER,"open",return_value=response):
            self.assertEqual(mod.candidates(mod.DEFAULT,"www.google.com","AAAA","direct"),["2001:4860:4860::8888"])
    def test_rank_and_isolate(self):
        def item(host,ip,ms,ok=True):return dict(host=host,ip=ip,total_ms=ms,ok=ok)
        data=[item("www.google.com","2001:db8::1",90),item("www.google.com","2001:db8::2",20),
              item("www.google.com","2001:db8::3",1,False),item("x.com","8.8.8.8",20)]
        self.assertEqual(mod.select_pins(data),"www.google.com=2001:db8::2,2001:db8::1;x.com=8.8.8.8")
        self.assertEqual(mod.select_pins([data[2]]),"")
    def test_probe_stage_and_hostname_verification(self):
        raw=MagicMock(); raw.__enter__.return_value=raw
        tls=MagicMock();tls.__enter__.return_value=tls
        tls.makefile.return_value=io.BytesIO(b"HTTP/1.1 200 OK\r\n")
        with patch.object(mod.socket,"socket",return_value=raw),patch.object(mod.CONTEXT,"wrap_socket",return_value=tls) as wrap:
            result=mod.probe("www.google.com","2001:4860:4860::8888","native",1)
            self.assertTrue(result["ok"])
            self.assertEqual(result["http_status"],200)
            wrap.assert_called_once_with(raw,server_hostname="www.google.com")
            raw.connect.assert_called_once_with(("2001:4860:4860::8888",443,0,0))
        with patch.object(mod.socket,"socket",return_value=raw),patch.object(mod.CONTEXT,"wrap_socket",side_effect=mod.ssl.SSLCertVerificationError("bad certificate")):
            result=mod.probe("x.com","8.8.8.8","native",1)
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"],"TLS")
    def test_tcp_failure(self):
        raw=MagicMock();raw.__enter__.return_value=raw;raw.connect.side_effect=TimeoutError("timeout")
        with patch.object(mod.socket,"socket",return_value=raw):
            result=mod.probe("x.com","8.8.8.8","native",1)
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"],"TCP")

    def test_offline_candidates_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "candidates.json"
            jobs = [("www.google.com", "2001:4860:4860::8888", "native", 5),
                    ("x.com", "8.8.8.8", "native", 5)]
            mod.save_candidates(path, mod.DEFAULT, jobs, [])
            with patch.object(mod.OPENER, "open", side_effect=AssertionError("offline DNS request")):
                loaded, errors = mod.load_candidates(path, mod.DEFAULT, ["www.google.com"], 3)
            self.assertEqual(loaded, [("www.google.com", "2001:4860:4860::8888", "native", 3)])
            self.assertEqual(errors, [])
            with self.assertRaises(ValueError):
                mod.load_candidates(path, "https://other.example", mod.HOSTS, 3)

if __name__=="__main__":
    unittest.main()
