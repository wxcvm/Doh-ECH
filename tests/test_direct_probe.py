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

    def test_public_fallback_after_project_403(self):
        denied = mod.urllib.error.HTTPError("https://dohech.dpdns.org/api/query", 403, "Forbidden", {}, None)
        valid = {"Status": 0, "Question": [{"name": "www.google.com.", "type": 28}],
                 "Answer": [{"type": 28, "data": "2001:4860:4860::8888"},
                            {"type": 5, "data": "alias.example."}]}
        with patch.object(mod, "read_dns_json", side_effect=[denied, valid]) as read:
            self.assertEqual(mod.candidates(mod.DEFAULT, "www.google.com", "AAAA", "direct"),
                             ["2001:4860:4860::8888"])
            self.assertIn("https://dns.google/resolve?", read.call_args_list[1].args[0])
        with patch.object(mod, "read_dns_json", side_effect=denied) as read:
            with self.assertRaises(RuntimeError):
                mod.candidates(mod.DEFAULT, "www.google.com", "AAAA", "rule")
            self.assertEqual(read.call_count, 1)

    def test_public_fallback_rejects_mismatched_question(self):
        wrong = {"Status": 0, "Question": [{"name": "other.example.", "type": 1}],
                 "Answer": [{"type": 1, "data": "8.8.8.8"}]}
        valid = {"Status": 0, "Question": [{"name": "x.com.", "type": 1}],
                 "Answer": [{"type": 1, "data": "8.8.4.4"}]}
        with patch.object(mod, "read_dns_json", side_effect=[OSError("timeout"), wrong, valid]):
            self.assertEqual(mod.candidates(mod.DEFAULT, "x.com", "A", "direct"), ["8.8.4.4"])

    def test_tls_control_only_chain_verified(self):
        raw=MagicMock(); raw.__enter__.return_value=raw
        tls=MagicMock(); tls.__enter__.return_value=tls; tls.version.return_value="TLSv1.3"
        context=MagicMock()
        context.wrap_socket.return_value=tls
        with patch.object(mod.ssl,"create_default_context",return_value=context), patch.object(mod.socket,"socket",return_value=raw):
            normal=mod.tls_check("x.com","162.159.140.229","TLS1.3",3)
            self.assertTrue(normal["hostname_verified"])
            context.wrap_socket.assert_called_with(raw,server_hostname="x.com")
            control=mod.tls_check("x.com","162.159.140.229","TLS1.3-no-SNI",3)
            self.assertFalse(control["hostname_verified"])
            self.assertFalse(context.check_hostname)
            context.wrap_socket.assert_called_with(raw,server_hostname=None)
            tls.sendall.assert_not_called()

    def test_tls_diagnose_only_prior_tls_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/"report.json"
            path.write_text(json.dumps({"results":[
                {"host":"x.com","ip":"162.159.140.229","stage":"TLS","ok":False,"tcp_ms":20},
                {"host":"x.com","ip":"8.8.8.8","stage":"TCP","ok":False},
                {"host":"www.google.com","ip":"8.8.4.4","stage":"TLS","ok":False}]}))
            def result(host,ip,mode,timeout):
                return dict(host=host,ip=ip,mode=mode,stage="TLS",ok=False)
            original_open=open
            with patch.object(mod,"tls_check",side_effect=result) as check, patch("builtins.open", wraps=original_open) as opened:
                # Redirect only the generated diagnostic report; retain actual input reading.
                def redirect(name,*args,**kwargs):
                    return original_open(pathlib.Path(tmp)/"out.json" if name=="direct-tls-diagnosis.json" else name,*args,**kwargs)
                opened.side_effect=redirect
                mod.diagnose_tls(path,["x.com"],3)
            self.assertEqual(check.call_count,3)
            self.assertTrue(all(c.args[1]=="162.159.140.229" for c in check.call_args_list))

    def test_expanded_native_sources_and_https(self):
        def reply(endpoint, host, kind):
            if kind == "HTTPS":
                return ['1 . alpn="h3,h2"']
            if kind == "AAAA":
                return ["2001:4860:4860::8888"] if "dns.google" in endpoint else ["2001:4860:4860::8844"]
            return ["8.8.8.8"]
        with patch.object(mod, "public_dns", side_effect=reply) as dns:
            jobs, errors, https = mod.collect_expanded(["www.google.com"], 3)
        self.assertEqual(dns.call_count, 6)
        self.assertEqual(len(jobs), 3)
        self.assertEqual(errors, [])
        self.assertEqual(len(https), 2)
        self.assertEqual({j[2] for j in jobs}, {"native-google", "native-cloudflare"})
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)/"candidates.json"
            mod.save_candidates(path, mod.DEFAULT, jobs, errors, https)
            self.assertEqual(mod.load_candidates(path, mod.DEFAULT, mod.HOSTS, 3)[0], jobs)
            self.assertEqual(json.loads(path.read_text())["https_records"], https)

    def test_http3_only_verified_address(self):
        response = MagicMock(returncode=0, stdout="200 3 162.159.140.229 0", stderr="")
        with patch.object(mod.subprocess, "run", return_value=response) as run:
            result = mod.http3_probe("x.com", "162.159.140.229", "native-google", 3)
            self.assertTrue(result["ok"])
            cmd = run.call_args.args[0]
            self.assertIn("--http3-only", cmd)
            self.assertNotIn("--insecure", cmd)
            self.assertEqual(cmd[1], "-q")
            self.assertIn("x.com:443:162.159.140.229", cmd)
            self.assertIn("--noproxy", cmd)
        for output in ("200 2 162.159.140.229 0", "200 3 8.8.8.8 0",
                       "200 3 162.159.140.229 1", "403 3 162.159.140.229 0"):
            response.stdout = output
            with patch.object(mod.subprocess, "run", return_value=response):
                self.assertFalse(mod.http3_probe("x.com", "162.159.140.229", "native", 3)["ok"])

    def test_http3_feature_check(self):
        with patch.object(mod.subprocess, "run", return_value=MagicMock(returncode=0, stdout="Features: IPv6 SSL HTTP2", stderr="")):
            self.assertFalse(mod.curl_http3_available()[0])
        with patch.object(mod.subprocess, "run", return_value=MagicMock(returncode=0, stdout="Features: IPv6 SSL HTTP3", stderr="")):
            self.assertTrue(mod.curl_http3_available()[0])
        with patch.object(mod.subprocess, "run", side_effect=OSError("missing curl")):
            self.assertFalse(mod.curl_http3_available()[0])

if __name__=="__main__":
    unittest.main()
