#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import time
from datetime import datetime, date, timedelta
import requests


BASE = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"


def parse_date(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()


def log(msg: str, lvl: int, verbose: int) -> None:
    if verbose >= lvl:
        print(msg, file=sys.stderr)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def weekly_dates(start: date, end: date, weekday: int) -> list[date]:
    """weekday: 0=Mon ... 6=Sun"""
    d = start + timedelta(days=(weekday - start.weekday()) % 7)
    out = []
    while d <= end:
        out.append(d)
        d += timedelta(days=7)
    return out


def download(url: str, dest: str, retries: int, timeout: int, sleep: float, verbose: int) -> bool:
    tmp = dest + ".part"
    if os.path.exists(tmp):
        try:
            os.remove(tmp)
        except OSError:
            pass

    for attempt in range(1, retries + 1):
        try:
            log(f"  GET {url} (attempt {attempt}/{retries})", 2, verbose)
            with requests.get(url, stream=True, timeout=timeout) as r:
                if r.status_code == 404:
                    log(f"  404 Not Found: {url}", 1, verbose)
                    return False
                r.raise_for_status()

                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=256 * 1024):
                        if chunk:
                            f.write(chunk)

            os.replace(tmp, dest)  # atomic
            return True

        except Exception as e:
            log(f"  error: {e}", 1, verbose)
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            if attempt < retries:
                time.sleep(sleep)

    return False


def main() -> int:
    p = argparse.ArgumentParser(description="Download weekly EPSS snapshots (daily .csv.gz files) for 2025.")
    p.add_argument("--start", default="2025-01-01", help="Start date YYYY-MM-DD (default: 2025-01-01)")
    p.add_argument("--end", default="2025-12-31", help="End date YYYY-MM-DD (default: 2025-12-31)")
    p.add_argument("--weekday", default="mon", choices=["mon","tue","wed","thu","fri","sat","sun"],
                   help="Which weekday to download (default: mon)")
    p.add_argument("--outdir", default="data/epss_weekly_2025", help="Output directory")
    p.add_argument("--retries", type=int, default=5, help="Retries per file (default: 5)")
    p.add_argument("--timeout", type=int, default=45, help="HTTP timeout seconds (default: 45)")
    p.add_argument("--sleep", type=float, default=1.5, help="Sleep between retries/files (default: 1.5)")
    p.add_argument("--force", action="store_true", help="Re-download even if file exists")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Verbose (-v, -vv)")
    args = p.parse_args()

    start = parse_date(args.start)
    end = parse_date(args.end)
    if end < start:
        print("Error: --end must be >= --start", file=sys.stderr)
        return 2

    wd_map = {"mon":0,"tue":1,"wed":2,"thu":3,"fri":4,"sat":5,"sun":6}
    weekday = wd_map[args.weekday]

    ensure_dir(args.outdir)
    dates = weekly_dates(start, end, weekday)

    log(f"Planned: {len(dates)} files ({args.weekday.upper()}) from {start} to {end}", 1, args.verbose)

    ok = skip = fail = 0
    for i, d in enumerate(dates, 1):
        ds = d.strftime("%Y-%m-%d")
        fn = f"epss_scores-{ds}.csv.gz"
        dest = os.path.join(args.outdir, fn)
        url = BASE.format(d=ds)

        if os.path.exists(dest) and not args.force:
            skip += 1
            log(f"[{i}/{len(dates)}] SKIP {fn}", 1, args.verbose)
            continue

        log(f"[{i}/{len(dates)}] DL   {fn}", 1, args.verbose)
        if download(url, dest, args.retries, args.timeout, args.sleep, args.verbose):
            ok += 1
        else:
            fail += 1

        if args.sleep > 0:
            time.sleep(args.sleep)

    print(f"Done. OK={ok} SKIP={skip} FAIL={fail} OUTDIR={args.outdir}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
