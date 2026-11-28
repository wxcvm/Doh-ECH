import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("quota", Path(__file__).with_name("worker-quota.py"))
quota = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quota)

class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.window = quota.utc_window(datetime(2026,11,28,7,30,tzinfo=timezone(timedelta(hours=8))))

    def payload(self, total, scripts):
        return {"data":{"viewer":{"accounts":[{
            "total":[{"sum":{"requests":total}}],
            "scripts":[{"sum":{"requests":n},"dimensions":{"scriptName":name}} for name,n in scripts]
        }]}}}

    def test_utc_reset(self):
        start, end, reset = self.window
        self.assertEqual(quota.stamp(start), "2026-11-27T00:00:00Z")
        self.assertEqual(quota.stamp(end), "2026-11-27T23:30:00Z")
        self.assertEqual(quota.stamp(reset), "2026-11-28T00:00:00Z")

    def test_thresholds(self):
        for n, status in [(0,"normal"),(79999,"normal"),(80000,"warning"),(95000,"critical"),(100000,"exhausted"),(101000,"exhausted")]:
            result = quota.summarize(self.payload(n,[("doh-ech",n)]), *self.window)
            self.assertEqual(result["status"],status)
            self.assertEqual(result["estimated_remaining"],max(0,100000-n))

    def test_all_workers(self):
        result = quota.summarize(self.payload(85000,[("doh-ech",81000),("test",4000)]), *self.window)
        self.assertEqual(result["percent_used"],85)
        self.assertEqual(result["scripts"]["test"],4000)

    def test_errors_are_not_zero_usage(self):
        for data in [{"errors":[{"message":"denied"}]}, {"data":{"viewer":{"accounts":[]}}}, self.payload(10,[("test",1000)]), self.payload(-1,[])]:
            with self.assertRaises(ValueError):
                quota.summarize(data,*self.window)

if __name__ == "__main__":
    unittest.main()
