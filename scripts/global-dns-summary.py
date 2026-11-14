#!/usr/bin/env python3
"""Read global DNS metrics from Cloudflare Analytics Engine (no DNS request overhead)."""
import argparse
import json
import os
import re
import urllib.request

def query(dataset, hours):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", dataset):
        raise ValueError("Invalid dataset name")
    if not 1 <= hours <= 720:
        raise ValueError("hours must be between 1 and 720")
    return f"""SELECT blob1 AS outcome, blob2 AS cache,
    SUM(_sample_interval) AS requests,
    SUM(double1 * _sample_interval) AS total_ms
FROM {dataset}
WHERE index1 = 'doh' AND timestamp >= NOW() - INTERVAL '{hours}' HOUR
GROUP BY outcome, cache"""

def summarize(rows):
    total = sum(float(r["requests"]) for r in rows)
    outcomes, caches = {}, {}
    for r in rows:
        n = float(r["requests"])
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + n
        caches[r["cache"]] = caches.get(r["cache"], 0) + n
    dns = sum(n for k, n in outcomes.items() if k.isdecimal())
    return {"estimated_requests": total, "outcomes": outcomes, "cache": caches,
            "dns_responses": dns,
            "servfail_rate": outcomes.get("2", 0) / dns if dns else None,
            "cache_hit_rate": (caches.get("DOMESTIC_HIT", 0) + caches.get("INTERNATIONAL_HIT", 0)) / total if total else None,
            "avg_ms": sum(float(r["total_ms"]) for r in rows) / total if total else None}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", default="doh_ech")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--sql-only", action="store_true")
    a = p.parse_args()
    sql = query(a.dataset, a.hours)
    if a.sql_only:
        print(sql)
        return
    account = os.environ["CF_ACCOUNT_ID"]
    token = os.environ["CF_ANALYTICS_TOKEN"]
    if not re.fullmatch(r"[a-fA-F0-9]{32}", account):
        raise ValueError("Invalid Cloudflare account ID")
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/analytics_engine/sql",
        data=sql.encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"})
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.load(response)
    print(json.dumps({"hours": a.hours, **summarize(result["data"])}, indent=2))

if __name__ == "__main__":
    main()
