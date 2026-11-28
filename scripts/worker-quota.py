#!/usr/bin/env python3
"""Read account-wide Workers invocation estimates without invoking the DNS Worker."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import math
import os
import re
import sys
import urllib.request

QUERY = """query($a:string,$f:string,$t:string){
 viewer { accounts(filter:{accountTag:$a}) {
  total:workersInvocationsAdaptive(limit:1,filter:{datetime_geq:$f,datetime_lt:$t}) {
   sum { requests }
  }
  scripts:workersInvocationsAdaptive(limit:1000,filter:{datetime_geq:$f,datetime_lt:$t}) {
   sum { requests } dimensions { scriptName }
  }
 } }
}"""

def utc_window(now):
    if now.tzinfo is None:
        raise ValueError("timezone-aware time required")
    now = now.astimezone(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, now, start + timedelta(days=1)

def stamp(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")

def count(row):
    n = row["sum"]["requests"]
    if isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) or n < 0:
        raise ValueError("invalid request count")
    return n

def summarize(payload, start, end, reset, limit=100000, warn=80, critical=95):
    if payload.get("errors"):
        raise ValueError("Cloudflare GraphQL returned errors")
    accounts = payload["data"]["viewer"]["accounts"]
    if len(accounts) != 1:
        raise ValueError("expected exactly one authorized account")
    account = accounts[0]
    total_rows = account["total"]
    if len(total_rows) > 1:
        raise ValueError("unexpected total rows")
    total = count(total_rows[0]) if total_rows else 0
    scripts = {}
    for row in account["scripts"]:
        name = row["dimensions"].get("scriptName") or "(unknown)"
        scripts[name] = scripts.get(name, 0) + count(row)
    if sum(scripts.values()) > total + max(1, total * .01):
        raise ValueError("inconsistent totals; retry the analytics query")
    percent = total / limit * 100
    return {"from_utc": stamp(start), "as_of_utc": stamp(end),
            "reset_utc": stamp(reset), "daily_limit": limit,
            "estimated_requests": total, "estimated_remaining": max(0, limit-total),
            "percent_used": round(percent, 2),
            "status": "exhausted" if total >= limit else "critical" if percent >= critical else "warning" if percent >= warn else "normal",
            "scripts": dict(sorted(scripts.items(), key=lambda item: -item[1])),
            "source": "workersInvocationsAdaptive; sampled/delayed estimate, not authoritative billing"}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=100000)
    p.add_argument("--warn", type=float, default=80)
    p.add_argument("--critical", type=float, default=95)
    p.add_argument("--fail-on-warning", action="store_true")
    a = p.parse_args()
    if not (a.limit > 0 and 0 < a.warn < a.critical <= 100):
        p.error("require positive limit and 0 < warn < critical <= 100")
    account = os.environ.get("CF_ACCOUNT_ID", "")
    token = os.environ.get("CF_ANALYTICS_TOKEN", "")
    if not re.fullmatch(r"[a-fA-F0-9]{32}", account) or not token:
        p.error("set CF_ACCOUNT_ID and a read-only CF_ANALYTICS_TOKEN")
    start, end, reset = utc_window(datetime.now(timezone.utc))
    if stamp(start) == stamp(end):
        p.error("UTC day has just reset; retry after the first second")
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql",
        data=json.dumps({"query": QUERY, "variables": {"a":account,"f":stamp(start),"t":stamp(end)}}).encode(),
        headers={"Authorization": "Bearer "+token, "Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.load(response)
        result = summarize(payload, start, end, reset, a.limit, a.warn, a.critical)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Analytics unavailable: "+str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if a.fail_on_warning and result["status"] != "normal" else 0

if __name__ == "__main__":
    sys.exit(main())
