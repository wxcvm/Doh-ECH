import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("summary", pathlib.Path(__file__).with_name("global-dns-summary.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)

class SummaryTests(unittest.TestCase):
    def test_weighted(self):
        result = summary.summarize([
            {"outcome": "0", "cache": "DOMESTIC_HIT", "requests": 9, "total_ms": 90},
            {"outcome": "2", "cache": "none", "requests": 1, "total_ms": 100},
            {"outcome": "http_error", "cache": "none", "requests": 2, "total_ms": 20},
        ])
        self.assertEqual(result["estimated_requests"], 12)
        self.assertEqual(result["servfail_rate"], .1)
        self.assertEqual(result["cache_hit_rate"], .75)
        self.assertEqual(result["avg_ms"], 17.5)

    def test_empty(self):
        result = summary.summarize([])
        self.assertIsNone(result["avg_ms"])
        self.assertIsNone(result["servfail_rate"])
        self.assertIsNone(result["cache_hit_rate"])

    def test_sql(self):
        self.assertIn("SUM(_sample_interval)", summary.query("doh_ech", 24))
        with self.assertRaises(ValueError):
            summary.query("bad; DROP", 24)

if __name__ == "__main__":
    unittest.main()
