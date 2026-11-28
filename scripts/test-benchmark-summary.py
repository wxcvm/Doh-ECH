import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("summary",Path(__file__).with_name("benchmark-summary.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class BenchmarkTests(unittest.TestCase):
    def test_percentile(self):
        self.assertIsNone(m.percentile([], .95))
        self.assertEqual(m.percentile([50,10,20,30,40], .5),30)
        self.assertEqual(m.percentile([50,10,20,30,40], .95),50)

    def test_no_fast_failure_bias(self):
        base={"host":"example.com","type":1,"rcode_low4":0,"answers":1}
        rows=[dict(base,ms=20,cache="DOH_HIT"),dict(base,ms=100,cache="DOH_MISS"),
              dict(base,ms=1,rcode_low4=2),dict(base,ms=2,answers=0,outcome="nodata"),
              dict(base,ms=40),dict(base,ms=3,error="HTTP 429"),
              dict(base,ms=4,truncated=True),dict(base,type="system_https",ms=1),
              dict(base,ms=200,endpoint="baseline")]
        result=m.summarize(rows)
        target=next(r for r in result if r["endpoint"]=="target" and r["host"]=="all")
        self.assertEqual((target["samples"],target["positive"],target["nodata"],target["failures"]),(7,3,1,3))
        self.assertEqual((target["p50_ms"],target["p95_ms"]),(40,100))
        self.assertEqual((target["observed_hits"],target["observed_misses"],target["unknown_cache"]),(1,1,1))
        baseline=next(r for r in result if r["endpoint"]=="baseline" and r["host"]=="all")
        self.assertEqual(baseline["p50_ms"],200)

    def test_invalid_latency(self):
        base={"host":"example.com","type":1,"rcode_low4":0,"answers":1}
        for ms in [-1,float("nan"),float("inf"),None,True]:
            self.assertEqual(m.classify(dict(base,ms=ms)),"failure")

if __name__=="__main__":
    unittest.main()
