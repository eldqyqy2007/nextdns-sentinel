"""Fix: the Devices page counters ("Blocked-site visits" / "Other events") stayed frozen.

They were computed in the browser from the last 300 alerts. This patch makes them use the
per-device totals that /api/devices already returns (all-time, from the database), so they
update live.

Usage (from the repository root, next to nextdns_sentinel.py):

    python patches/device_counts_fix.py

It is safe to run more than once.
"""
import pathlib
import sys

path = pathlib.Path("nextdns_sentinel.py")
src = path.read_text(encoding="utf-8")
old = ("['Blocked-site visits',String(mine.filter(a=>a.category==='site').length)],"
       "['Other events',String(mine.filter(a=>a.category!=='site').length)]]")
new = ("['Blocked-site visits',String(x.blocked_count!=null?x.blocked_count:mine.filter(a=>a.category==='site').length)],"
       "['Other events',String(x.alert_count!=null?Math.max(0,x.alert_count-(x.blocked_count||0)):mine.filter(a=>a.category!=='site').length)]]")
if new in src:
    print("already patched")
    sys.exit(0)
if src.count(old) != 1:
    print("pattern not found:", src.count(old))
    sys.exit(1)
path.write_text(src.replace(old, new), encoding="utf-8")
print("patched")
