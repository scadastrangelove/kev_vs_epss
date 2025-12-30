#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KEV 2025 vs EPSS:
- Берём KEV CSV (CISA)
- Фильтруем записи по dateAdded=YEAR
- Для каждой CVE делаем 2 запроса EPSS:
    1) EPSS на дату dateAdded (историческое значение)
    2) EPSS "текущее" (без date) ИЛИ на конкретную дату --asof (если задано)
- Пишем CSV построчно (append), можно продолжать (--resume)
- -v / -vv для статуса и отладки

EPSS API docs: cve list supported but max 2000 chars; date gives historic values.
"""

import argparse
import csv
import datetime as dt
import io
import logging
import os
import sys
import time
from typing import Dict, Optional, Tuple

import requests

DEFAULT_KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
EPSS_API = "https://api.first.org/data/v1/epss"


def setup_logger(verbosity: int) -> logging.Logger:
    logger = logging.getLogger("kev-epss")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    if verbosity <= 0:
        ch.setLevel(logging.WARNING)
    elif verbosity == 1:
        ch.setLevel(logging.INFO)
    else:
        ch.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    ch.setFormatter(fmt)
    logger.handlers[:] = [ch]
    return logger


def http_get_json(
    session: requests.Session,
    url: str,
    params: Dict[str, str],
    timeout: int,
    retries: int,
    logger: logging.Logger,
    verbose_urls: bool = False,
) -> dict:
    backoff = 1.0
    last_exc: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        try:
            if verbose_urls:
                logger.debug("GET %s params=%s", url, params)
            r = session.get(url, params=params, timeout=timeout)
            if r.status_code in (429, 503, 502, 504):
                logger.info("HTTP %s (attempt %d/%d), backing off %.1fs", r.status_code, attempt, retries, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last_exc = e
            logger.info("Request failed (attempt %d/%d): %r; backoff %.1fs", attempt, retries, e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

    raise RuntimeError(f"Failed GET {url} params={params} after {retries} retries: {last_exc!r}")


def fetch_epss_one(
    session: requests.Session,
    cve: str,
    date_iso: Optional[str],
    timeout: int,
    retries: int,
    logger: logging.Logger,
    verbose_urls: bool = False,
) -> Tuple[Optional[float], Optional[float], Optional[str], Optional[str]]:
    """
    Возвращает: (epss, percentile, returned_date, error)
    - date_iso=None -> "текущее" (latest) значение
    - если данных нет -> (None, None, returned_date(None), None)
    - если ошибка -> (..., ..., ..., "error text")
    """
    params = {"cve": cve}
    if date_iso:
        params["date"] = date_iso

    try:
        js = http_get_json(session, EPSS_API, params, timeout, retries, logger, verbose_urls=verbose_urls)
        data = js.get("data") or []
        if not data:
            # total may be 0
            return None, None, None, None

        item = data[0]
        # sanity: CVE should match
        if (item.get("cve") or "").strip().upper() != cve.upper():
            return None, None, item.get("date"), f"Unexpected CVE in response: {item.get('cve')}"

        epss = float(item["epss"])
        pct = float(item["percentile"])
        rdate = item.get("date")

        # sanity ranges
        if not (0.0 <= epss <= 1.0) or not (0.0 <= pct <= 1.0):
            return None, None, rdate, f"Out-of-range values epss={epss}, percentile={pct}"

        return epss, pct, rdate, None

    except Exception as e:
        return None, None, None, repr(e)


def load_kev_rows(url: str, session: requests.Session, timeout: int) -> Tuple[list, list]:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    text = r.text
    f = io.StringIO(text)
    reader = csv.DictReader(f)
    rows = list(reader)
    return rows, (reader.fieldnames or [])


def read_done_cves(out_csv: str) -> set:
    done = set()
    if not os.path.exists(out_csv):
        return done
    with open(out_csv, "r", encoding="utf-8", newline="") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            c = (row.get("cveID") or "").strip()
            if c:
                done.add(c)
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev-url", default=DEFAULT_KEV_CSV_URL, help="KEV CSV URL (CISA)")
    ap.add_argument("--year", type=int, default=2025, help="Filter by KEV dateAdded year")
    ap.add_argument("--out", default="kev_2025_epss.csv", help="Output CSV path")
    ap.add_argument("--resume", action="store_true", help="Resume if --out already exists")
    ap.add_argument("--sleep", type=float, default=0.15, help="Sleep between EPSS requests")
    ap.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    ap.add_argument("--retries", type=int, default=6, help="Retries per EPSS request")
    ap.add_argument("--asof", default="", help="If set (YYYY-MM-DD), fetch 'current' EPSS at this date; else latest (no date)")
    ap.add_argument("-v", action="count", default=0, help="Verbose (-v, -vv)")
    args = ap.parse_args()

    logger = setup_logger(args.v)
    verbose_urls = args.v >= 2

    # Validate asof if provided
    asof = args.asof.strip()
    if asof:
        try:
            dt.date.fromisoformat(asof)
        except ValueError:
            raise SystemExit(f"--asof must be YYYY-MM-DD, got: {asof!r}")

    session = requests.Session()
    session.headers.update({"User-Agent": "kev-epss-single/1.0"})

    # Load KEV
    kev_rows, kev_fields = load_kev_rows(args.kev_url, session, args.timeout)
    required = {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate"}
    missing = required - set(kev_fields)
    if missing:
        raise SystemExit(f"KEV CSV missing columns: {sorted(missing)}; got={kev_fields}")

    # Filter year by dateAdded
    rows = []
    for r in kev_rows:
        da = (r.get("dateAdded") or "").strip()
        if da.startswith(f"{args.year}-"):
            cve = (r.get("cveID") or "").strip()
            if cve:
                rows.append(r)

    # Stable ordering: by dateAdded then cve
    rows.sort(key=lambda r: ((r.get("dateAdded") or "").strip(), (r.get("cveID") or "").strip()))

    if not rows:
        raise SystemExit(f"No KEV rows with dateAdded in {args.year}")

    # Resume
    done = set()
    if args.resume:
        done = read_done_cves(args.out)
        logger.warning("Resume enabled: %d CVEs already in %s", len(done), args.out)

    # Output CSV setup
    out_fields = [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
        "epss_at_dateAdded",
        "percentile_at_dateAdded",
        "epss_current",
        "percentile_current",
        "epss_current_date",
        "current_mode",
        "error_dateAdded",
        "error_current",
    ]

    write_header = not os.path.exists(args.out) or (not args.resume)

    # If resume and file exists, we append without rewriting header
    mode = "a" if (args.resume and os.path.exists(args.out)) else "w"
    with open(args.out, mode, encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        if mode == "w":
            w.writeheader()

        processed = 0
        skipped = 0
        err_added = 0
        err_current = 0

        total = len(rows)
        for idx, r in enumerate(rows, start=1):
            cve = (r.get("cveID") or "").strip()
            if not cve:
                continue
            if cve in done:
                skipped += 1
                continue

            date_added = (r.get("dateAdded") or "").strip()

            if args.v >= 1:
                logger.info("[%d/%d] %s (dateAdded=%s)", idx, total, cve, date_added)

            # 1) EPSS at dateAdded
            epss_a, pct_a, rdate_a, err_a = fetch_epss_one(
                session, cve, date_added, args.timeout, args.retries, logger, verbose_urls=verbose_urls
            )
            if err_a:
                err_added += 1

            # 2) EPSS current: by default latest (no date); optionally by --asof
            current_mode = "latest" if not asof else f"asof:{asof}"
            epss_b, pct_b, rdate_b, err_b = fetch_epss_one(
                session, cve, (asof if asof else None), args.timeout, args.retries, logger, verbose_urls=verbose_urls
            )
            if err_b:
                err_current += 1

            row_out = {
                "cveID": cve,
                "vendorProject": r.get("vendorProject", ""),
                "product": r.get("product", ""),
                "vulnerabilityName": r.get("vulnerabilityName", ""),
                "dateAdded": date_added,
                "dueDate": r.get("dueDate", ""),
                "knownRansomwareCampaignUse": r.get("knownRansomwareCampaignUse", ""),
                "epss_at_dateAdded": "" if epss_a is None else f"{epss_a:.9f}",
                "percentile_at_dateAdded": "" if pct_a is None else f"{pct_a:.9f}",
                "epss_current": "" if epss_b is None else f"{epss_b:.9f}",
                "percentile_current": "" if pct_b is None else f"{pct_b:.9f}",
                "epss_current_date": rdate_b or "",
                "current_mode": current_mode,
                "error_dateAdded": err_a or "",
                "error_current": err_b or "",
            }

            w.writerow(row_out)
            f.flush()  # чтобы прогресс сохранялся даже при падении
            processed += 1

            time.sleep(args.sleep)

    logger.warning(
        "Done. total=%d processed=%d skipped=%d err_dateAdded=%d err_current=%d out=%s",
        len(rows), processed, skipped, err_added, err_current, args.out
    )


if __name__ == "__main__":
    main()
