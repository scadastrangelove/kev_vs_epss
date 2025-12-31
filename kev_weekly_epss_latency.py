#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KEV × weekly EPSS extractor + latency plots

What it does:
1) Reads KEV CSV with columns: cveID, dateAdded (others allowed)
2) Iterates weekly EPSS snapshot files (csv or csv.gz):
   - Parses score_date from the first comment line:
     "#model_version:...,score_date:YYYY-mm-ddT00:00:00+0000"
   - Streams rows, keeps only CVEs present in KEV
3) Writes extracted panel data to CSV:
   columns: cve, kev_dateAdded, snapshot_date, epss, percentile
4) Builds:
   Figure 5A: time-to-threshold ECDF for EPSS >= {0.001, 0.01, 0.1}
   Figure 5B: catch-up latency ECDF for EPSS growth >= {10x, 100x} from baseline

Notes:
- Weekly resolution: latency is quantized by snapshot cadence (± up to ~6 days).
- Baseline EPSS for a CVE is the first snapshot on/after dateAdded (not same-day exact).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, date
from typing import Dict, Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


SCORE_DATE_RE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})T")


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_iso_date(s: str) -> date:
    # Accept "YYYY-MM-DD" or ISO timestamp prefix
    s = s.strip()
    if len(s) >= 10:
        s = s[:10]
    return datetime.strptime(s, "%Y-%m-%d").date()


def open_maybe_gz(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, "rt", encoding="utf-8", newline="")


def parse_snapshot_date_from_header(first_line: str, fallback_from_name: Optional[str]) -> Optional[date]:
    m = SCORE_DATE_RE.search(first_line or "")
    if m:
        return parse_iso_date(m.group(1))
    if fallback_from_name:
        # Try epss_scores-YYYY-MM-DD.csv(.gz)
        m2 = re.search(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv", fallback_from_name)
        if m2:
            return parse_iso_date(m2.group(1))
    return None


def list_snapshot_files(folder: str) -> List[str]:
    files = []
    for fn in os.listdir(folder):
        if fn.startswith("epss_scores-") and (fn.endswith(".csv") or fn.endswith(".csv.gz")):
            files.append(os.path.join(folder, fn))
    # sort by date in filename if possible
    def key(p: str):
        m = re.search(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv", os.path.basename(p))
        return m.group(1) if m else os.path.basename(p)
    files.sort(key=key)
    return files


def read_kev_table(path: str, verbose: int = 0) -> Dict[str, date]:
    """
    Returns mapping: cve -> dateAdded
    """
    import pandas as pd  # local import to keep hard deps minimal
    df = pd.read_csv(path, dtype=str)
    if "cveID" not in df.columns or "dateAdded" not in df.columns:
        raise RuntimeError(f"KEV file must contain columns cveID,dateAdded. Got: {list(df.columns)}")

    out: Dict[str, date] = {}
    bad = 0
    for _, row in df.iterrows():
        cve = str(row["cveID"]).strip()
        if not cve or cve == "nan":
            continue
        try:
            d = parse_iso_date(str(row["dateAdded"]))
            out[cve] = d
        except Exception:
            bad += 1

    if verbose:
        eprint(f"[KEV] loaded {len(out)} CVEs (bad dateAdded: {bad})")
    return out


@dataclass
class PanelRow:
    cve: str
    kev_dateAdded: date
    snapshot_date: date
    epss: float
    percentile: float


def extract_weekly_panel(
    kev_map: Dict[str, date],
    snapshot_folder: str,
    verbose: int = 0,
) -> List[PanelRow]:
    kev_set = set(kev_map.keys())
    files = list_snapshot_files(snapshot_folder)
    if verbose:
        eprint(f"[SNAP] found {len(files)} snapshot files in {snapshot_folder}")

    rows: List[PanelRow] = []
    missing_score_date = 0
    matched_total = 0

    for idx, path in enumerate(files, 1):
        fn = os.path.basename(path)
        with open_maybe_gz(path) as f:
            # Read first line: comment with model_version/score_date
            first = f.readline()
            snap_date = parse_snapshot_date_from_header(first, fn)
            if snap_date is None:
                missing_score_date += 1
                if verbose:
                    eprint(f"[{idx}/{len(files)}] WARN: cannot parse score_date from header/file: {fn}")
                # Skip (or you can fallback to filename only)
                continue

            # Next line should be CSV header: cve,epss,percentile
            header = f.readline()
            if "cve" not in header.lower():
                # Some files may have no comment line; if so, treat 'header' as actual header and parse snap_date from fn
                # We already used fn fallback; proceed anyway.
                pass

            reader = csv.DictReader(f, fieldnames=["cve", "epss", "percentile"])
            # DictReader assumes we've already consumed the real header line; we did.
            matched = 0
            for r in reader:
                cve = (r.get("cve") or "").strip()
                if cve in kev_set:
                    try:
                        epss = float(r.get("epss") or "nan")
                        pct = float(r.get("percentile") or "nan")
                    except Exception:
                        continue
                    rows.append(
                        PanelRow(
                            cve=cve,
                            kev_dateAdded=kev_map[cve],
                            snapshot_date=snap_date,
                            epss=epss,
                            percentile=pct,
                        )
                    )
                    matched += 1

            matched_total += matched
            if verbose:
                eprint(f"[{idx}/{len(files)}] {fn} score_date={snap_date} matched={matched}")

    if verbose:
        eprint(f"[SNAP] matched rows total: {matched_total} | missing score_date files: {missing_score_date}")
    return rows


def write_panel_csv(rows: List[PanelRow], out_csv: str) -> None:
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve", "kev_dateAdded", "snapshot_date", "epss", "percentile"])
        for r in rows:
            w.writerow([r.cve, r.kev_dateAdded.isoformat(), r.snapshot_date.isoformat(), f"{r.epss:.10f}", f"{r.percentile:.10f}"])


def ecdf_xy(values: List[float]) -> Tuple[List[float], List[float]]:
    xs = sorted(values)
    n = len(xs)
    ys = [(i + 1) / n for i in range(n)]
    return xs, ys


def build_latency_metrics(rows: List[PanelRow], thresholds: List[float], growth_factors: List[float]):
    """
    For each CVE:
    - baseline = first snapshot on/after kev_dateAdded (weekly resolution)
    - time_to_threshold[t] = first snapshot >= threshold; days since kev_dateAdded
    - time_to_growth[g] = first snapshot >= baseline*growth_factor; days since kev_dateAdded
    Returns dicts: {threshold: [days...]}, {growth: [days...]} (only observed, censored removed)
    Also returns counts for censored for reporting.
    """
    # group by cve
    by_cve: Dict[str, List[PanelRow]] = {}
    kev_date: Dict[str, date] = {}
    for r in rows:
        by_cve.setdefault(r.cve, []).append(r)
        kev_date[r.cve] = r.kev_dateAdded

    # sort each series by snapshot_date
    for cve in by_cve:
        by_cve[cve].sort(key=lambda x: x.snapshot_date)

    time_to_thr: Dict[float, List[int]] = {t: [] for t in thresholds}
    time_to_g: Dict[float, List[int]] = {g: [] for g in growth_factors}

    cens_thr: Dict[float, int] = {t: 0 for t in thresholds}
    cens_g: Dict[float, int] = {g: 0 for g in growth_factors}

    used_cves = 0

    for cve, series in by_cve.items():
        d0 = kev_date[cve]

        # baseline: first snapshot on/after d0
        baseline_row = None
        for r in series:
            if r.snapshot_date >= d0:
                baseline_row = r
                break
        if baseline_row is None:
            # no data after dateAdded -> skip
            continue

        used_cves += 1
        baseline_epss = baseline_row.epss

        # time-to-threshold
        for t in thresholds:
            hit = None
            for r in series:
                if r.snapshot_date >= d0 and r.epss >= t:
                    hit = r
                    break
            if hit is None:
                cens_thr[t] += 1
            else:
                time_to_thr[t].append((hit.snapshot_date - d0).days)

        # catch-up growth relative to baseline
        for g in growth_factors:
            target = baseline_epss * g
            hit = None
            for r in series:
                if r.snapshot_date >= d0 and r.epss >= target:
                    hit = r
                    break
            if hit is None:
                cens_g[g] += 1
            else:
                time_to_g[g].append((hit.snapshot_date - d0).days)

    return time_to_thr, cens_thr, time_to_g, cens_g, used_cves


def plot_time_to_threshold_ecdf(time_to_thr: Dict[float, List[int]], out_png: str):
    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    for t, days in sorted(time_to_thr.items(), key=lambda x: x[0]):
        if not days:
            continue
        xs, ys = ecdf_xy(days)
        ax.plot(xs, ys, linewidth=2, label=f"EPSS ≥ {t:g}")
    ax.set_xlabel("Days since KEV inclusion date (dateAdded)")
    ax.set_ylabel("Cumulative share of KEV vulnerabilities")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, pos: f"{v*100:.0f}%"))
    ax.grid(True, which="both", linewidth=0.5, alpha=0.4)
    ax.legend()
    os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)
    fig.savefig(out_png, dpi=260, bbox_inches="tight")
    plt.close(fig)


def plot_catchup_latency_ecdf(time_to_g: Dict[float, List[int]], out_png: str):
    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    for g, days in sorted(time_to_g.items(), key=lambda x: x[0]):
        if not days:
            continue
        xs, ys = ecdf_xy(days)
        ax.plot(xs, ys, linewidth=2, label=f"EPSS ≥ baseline × {int(g)}")
    ax.set_xlabel("Days since KEV inclusion date (dateAdded)")
    ax.set_ylabel("Cumulative share of KEV vulnerabilities")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, pos: f"{v*100:.0f}%"))
    ax.grid(True, which="both", linewidth=0.5, alpha=0.4)
    ax.legend()
    os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)
    fig.savefig(out_png, dpi=260, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract weekly EPSS for KEV CVEs and build latency plots.")
    ap.add_argument("--kev-csv", required=True, help="KEV table CSV containing cveID and dateAdded")
    ap.add_argument("--snap-dir", required=True, help="Folder with epss_scores-YYYY-MM-DD.csv(.gz) weekly snapshots")
    ap.add_argument("--out-csv", default="kev_weekly_epss_2025.csv", help="Output extracted panel CSV")
    ap.add_argument("--fig-dir", default="figures", help="Output directory for figures")
    ap.add_argument("--thresholds", default="0.001,0.01,0.1", help="Comma-separated EPSS thresholds")
    ap.add_argument("--growth", default="10,100", help="Comma-separated EPSS growth factors from baseline")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="Verbose (-v, -vv)")
    args = ap.parse_args()

    thresholds = [float(x.strip()) for x in args.thresholds.split(",") if x.strip()]
    growth = [float(x.strip()) for x in args.growth.split(",") if x.strip()]

    kev_map = read_kev_table(args.kev_csv, verbose=args.verbose)
    rows = extract_weekly_panel(kev_map, args.snap_dir, verbose=args.verbose)
    if not rows:
        eprint("No rows extracted. Check paths and file formats.")
        return 2

    write_panel_csv(rows, args.out_csv)
    if args.verbose:
        eprint(f"[OUT] wrote panel CSV: {args.out_csv} (rows={len(rows)})")

    time_to_thr, cens_thr, time_to_g, cens_g, used_cves = build_latency_metrics(
        rows, thresholds=thresholds, growth_factors=growth
    )

    os.makedirs(args.fig_dir, exist_ok=True)
    fig5a = os.path.join(args.fig_dir, "fig5a_time_to_threshold_ecdf.png")
    fig5b = os.path.join(args.fig_dir, "fig5b_catchup_latency_ecdf.png")

    plot_time_to_threshold_ecdf(time_to_thr, fig5a)
    plot_catchup_latency_ecdf(time_to_g, fig5b)

    # Print summary (good for paper text)
    eprint("\n=== Latency summary (weekly resolution) ===")
    eprint(f"KEV CVEs with at least one snapshot on/after dateAdded: {used_cves}")
    for t in sorted(thresholds):
        obs = len(time_to_thr[t])
        eprint(f"Time-to EPSS≥{t:g}: observed={obs}, censored={cens_thr[t]}")
    for g in sorted(growth):
        obs = len(time_to_g[g])
        eprint(f"Time-to EPSS≥baseline×{int(g)}: observed={obs}, censored={cens_g[g]}")

    eprint(f"\nFigures:\n  {fig5a}\n  {fig5b}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
