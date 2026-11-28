#!/usr/bin/env python3
"""Summarize balanced-probe JSON without issuing additional DNS requests."""
import argparse
import json
import math
from collections import defaultdict

def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered)*p)-1)], 2)

def classify(row):
    if row.get("error") or row.get("truncated") or row.get("rcode_low4") != 0:
        return "failure"
    if row.get("outcome") == "nodata" or row.get("answers") == 0:
        return "nodata"
    ms = row.get("ms")
    if isinstance(ms, bool) or not isinstance(ms, (int,float)) or not math.isfinite(ms) or ms < 0:
        return "failure"
    return "positive"

def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        if type(row.get("type")) is not int:
            continue
        endpoint = row.get("endpoint", "target")
        host = row["host"]
        kind = str(row["type"])
        for group in [(endpoint,"all","all"),(endpoint,host,kind)]:
            groups[group].append(row)
    output = []
    for (endpoint,host,kind), samples in sorted(groups.items()):
        positive = [r for r in samples if classify(r) == "positive"]
        failures = sum(classify(r) == "failure" for r in samples)
        nodata = sum(classify(r) == "nodata" for r in samples)
        observed = [r for r in positive if r.get("cache")]
        hits = [r for r in observed if r["cache"] in ("DOMESTIC_HIT","INTERNATIONAL_HIT","DOH_HIT")]
        misses = [r for r in observed if r["cache"] in ("DOMESTIC_MISS","INTERNATIONAL_MISS","DOH_MISS")]
        output.append({"endpoint":endpoint,"host":host,"type":kind,"samples":len(samples),
          "positive":len(positive),"nodata":nodata,"failures":failures,
          "failure_rate":round(failures/len(samples),4),
          "p50_ms":percentile([r["ms"] for r in positive],.5),
          "p95_ms":percentile([r["ms"] for r in positive],.95),
          "observed_hits":len(hits),"observed_misses":len(misses),
          "unknown_cache":len(positive)-len(hits)-len(misses),
          "hit_p50_ms":percentile([r["ms"] for r in hits],.5),
          "miss_p50_ms":percentile([r["ms"] for r in misses],.5)})
    return output

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("input")
    p.add_argument("--markdown",action="store_true")
    a=p.parse_args()
    with open(a.input,encoding="utf-8") as source:
        data=json.load(source)
    rows=summarize(data["samples"])
    if not rows:
        p.error("no DNS samples")
    if not a.markdown:
        print(json.dumps(rows,indent=2))
        return
    print("| Endpoint | Host | Type | Samples | Positive | NODATA | Failures | P50 ms | P95 ms | Cache H/M/? |")
    print("|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        values=[r[k] for k in ("endpoint","host","type","samples","positive","nodata","failures","p50_ms","p95_ms")]
        values.append(f'{r["observed_hits"]}/{r["observed_misses"]}/{r["unknown_cache"]}')
        print("| "+" | ".join("—" if x is None else str(x).replace("|","\\|") for x in values)+" |")
    print("\nLatency percentiles cover positive replies only; NODATA and failures are separate. Small sample tails are descriptive, not stable estimates. Missing cache headers are unknown. No end-to-end ECH claim.")

if __name__=="__main__":
    main()
