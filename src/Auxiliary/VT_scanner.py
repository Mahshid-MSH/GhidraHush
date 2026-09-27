#!/usr/bin/env python3
"""
vt_scanner.py -- VT free-tier client for variant detection evaluation.
Quota: 4 req/min (ALL requests count), 500 uploads/day. Caches by sha256
in SQLite, survives restarts, known files cost nothing.
Usage:
  python vt_scanner.py <dir-or-file>          # scan .exe/.dll files
  python vt_scanner.py <dir-or-file> --all    # scan every file
  python vt_scanner.py --report               # print summary from cache
  python vt_scanner.py --excel out.xlsx       # export cached results
  python vt_scanner.py --excel out.xlsx --baseline-sha <sha> \
      --manifest variants/manifest.json       # + provenance/delta columns
"""

import os, sys, time, json, sqlite3, hashlib, argparse, re
from collections import Counter
from datetime import datetime, timezone
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

import requests
from dotenv import load_dotenv

H = "https://www.virustotal.com/api/v3"
DB = "vt_results.db"
EXE_EXTS = {".exe", ".dll", ".sys"}

# ---------------------------------------------------------------- rate limiter
class VTThrottle:
    """Free tier: 4 requests/min across lookups + uploads + polls alike."""
    MIN_INTERVAL = 16.0

    def __init__(self):
        self._last = 0.0

    def wait(self):
        now = time.time()
        delta = now - self._last
        if delta < self.MIN_INTERVAL:
            time.sleep(self.MIN_INTERVAL - delta)
        self._last = time.time()

throttle = VTThrottle()

def vt_request(method, url, api_key, **kw):
    """Single throttled request with 429/Retry-After handling."""
    headers = {"x-apikey": api_key}
    for attempt in range(5):
        throttle.wait()
        r = requests.request(method, url, headers=headers, timeout=60, **kw)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 60))
            print(f"  [429] rate limited -- sleeping {wait}s")
            time.sleep(wait)
            continue
        return r
    r.raise_for_status()
    return r

# ---------------------------------------------------------------- storage
def _db():
    con = sqlite3.connect(DB)
    # v2 schema: file_name column. Migrate transparently if upgrading.
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        sha256 TEXT PRIMARY KEY, detection_count INTEGER,
        engines_total INTEGER, detections_json TEXT, scan_date TEXT,
        file_name TEXT)""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(scans)").fetchall()]
    if "file_name" not in cols:
        con.execute("ALTER TABLE scans ADD COLUMN file_name TEXT")
        con.commit()
    return con

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _save(con, j, file_name=None):
    attrs = j["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    scan_date = datetime.fromtimestamp(
        attrs.get("last_analysis_date", time.time()), tz=timezone.utc
    ).isoformat()
    con.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
                (j["data"]["id"],
                 stats["malicious"] + stats["suspicious"],
                 sum(stats.values()),
                 json.dumps({"last_analysis_stats": stats,
                             "last_analysis_results":
                                 attrs["last_analysis_results"]}, indent=1),
                 scan_date, file_name))

# ---------------------------------------------------------------- core
def scan_file(path, api_key, max_poll=600):
    con = _db()
    sha = sha256_of(path)
    fname = os.path.basename(path)          # ONCE, before any branch
    row = con.execute("SELECT * FROM scans WHERE sha256=?", (sha,)).fetchone()
    if row:
        print(f"  cached:  {sha[:16]}... -> {row[1]}/{row[2]} detections")
        return row[1]

    # 1) known to VT? -- report lookup costs NO upload quota.
    r = vt_request("GET", f"{H}/files/{sha}", api_key)
    if r.status_code == 200:
        j = r.json()
        _save(con, j, file_name=fname); con.commit()
        n = j["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"  known:   {sha[:16]}... -> {n} detections (lookup only)")
        return n
    if r.status_code in (401, 403):
        raise SystemExit("VT auth failed -- check VT_API_KEY in .env")

    # 2) upload
    with open(path, "rb") as f:
        r = vt_request("POST", f"{H}/files/upload", api_key,
                       files={"file": (os.path.basename(path), f)})
    if r.status_code != 200:
        print(f"  upload failed for {sha[:16]}... (HTTP {r.status_code}): "
              f"{r.text[:200]}")
        return None
    analysis_id = r.json()["data"]["id"]
    print(f"  uploaded {sha[:16]}... -- polling analysis {analysis_id[:16]}...")

    # 3) poll
    deadline = time.time() + max_poll
    while time.time() < deadline:
        time.sleep(15)
        ar = vt_request("GET", f"{H}/analyses/{analysis_id}", api_key)
        if ar.status_code != 200:
            continue
        if ar.json()["data"]["attributes"]["status"] == "completed":
            fr = vt_request("GET", f"{H}/files/{sha}", api_key)
            _save(con, fr.json(), file_name=fname); con.commit()
            n = fr.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
            print(f"  scanned: {sha[:16]}... -> {n} detections")
            return n
    print(f"  TIMEOUT: {sha[:16]}... still queued after {max_poll}s "
          f"(rerun later to pick it up)")
    return None

def report():
    con = _db()
    rows = con.execute("SELECT sha256, detection_count, engines_total, "
                       "scan_date, file_name FROM scans "
                       "ORDER BY scan_date").fetchall()
    print(f"\n{'sha256':<20} {'det':>5} {'eng':>5}  {'name':<28} scan_date")
    print("-" * 90)
    for sha, det, total, date, name in rows:
        print(f"{sha[:18]}... {det:>5}/{total:<3}  {name or '?':<28} {date}")
    print(f"\n{len(rows)} cached result(s) in {DB}")

# ---------------------------------------------------------------- driver
def collect_files(target, scan_all_exts):
    if os.path.isfile(target):
        return [target]
    out = []
    for root, _, files in os.walk(target):
        for f in sorted(files):
            p = os.path.join(root, f)
            if scan_all_exts or os.path.splitext(f)[1].lower() in EXE_EXTS:
                out.append(p)
    return out

# ============================================================
# Excel export
# ============================================================

def export_excel(xlsx_path="vt_results.xlsx",
                 manifest_path="variants/manifest.json",
                 baseline_sha=None):

    con = _db()
    rows = con.execute(
        "SELECT sha256, detection_count, engines_total, detections_json, "
        "scan_date, file_name FROM scans ORDER BY scan_date").fetchall()

    # provenance join: sha256 -> (variant_id, plan, subset, seed, dir)
    prov = {}
    if manifest_path and os.path.isfile(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            for v in json.load(f):
                exe = None
                for cand in ("linked.exe", "a.exe", "out.exe"):
                    p = os.path.join(v.get("dir", ""), cand)
                    if os.path.isfile(p):
                        exe = p
                        break
                if exe and os.path.isfile(exe):
                    prov[sha256_of(exe)] = {
                        "variant_id": v.get("id"),
                        "plan": " > ".join(v.get("plan", [])),
                        "n_techniques": len(v.get("plan", [])),
                        "subset_size": len(v.get("subset", [])),
                        "seed": v.get("seed"),
                        "dir": v.get("dir"),
                    }

    wb = Workbook()

    # ---------------- Sheet 1: Variants ----------------
    ws = wb.active
    ws.title = "Variants"
    headers = [
        "File Name", "SHA256", "Detection Rate (%)", "Detections",
        "Engines Total", "Malicious", "Suspicious", "Undetected",
        "Delta vs Baseline (pp)", "Variant ID", "Plan (technique order)",
        "# Techniques", "Subset Size", "Seed", "Scan Date (UTC)",
        "Top Detection Names", "First Seen (days)",
    ]
    ws.append(headers)
    for c in ws[1]:
        c.font = Font(bold=True)
        c.fill = PatternFill("solid", fgColor="DDDDDD")
        c.alignment = Alignment(wrap_text=True, vertical="top")

    baseline_det = None
    enriched = []
    for sha, det, total, detj, date, db_name in rows:
        rec = json.loads(detj)
        # format shim: new rows wrap stats+results; old rows hold results only
        if "last_analysis_stats" in rec:
            rec = rec["last_analysis_results"]
        engines = rec.values() if isinstance(rec, dict) else []
        names = [e.get("result") for e in engines
                 if isinstance(e, dict) and e.get("result")]
        fam = Counter()
        for n in names:
            fam[" ".join(str(n).split()[:2])] += 1
        top_fams = "; ".join(f"{k} ({v})" for k, v in fam.most_common(5))
        days = None
        for e in engines:
            fd = e.get("first_seen") if isinstance(e, dict) else None
            if fd:
                try:
                    d = datetime.fromisoformat(fd.replace("Z", "+00:00"))
                    days = (datetime.now(timezone.utc) - d).days
                    break
                except Exception:
                    pass
        is_baseline = (baseline_sha and sha == baseline_sha)
        if is_baseline:
            baseline_det = det
        enriched.append((sha, det, total, rec, date, names, top_fams,
                         days, is_baseline, db_name))

    # second pass: filename from DB first, then manifest, then hash
    for (sha, det, total, rec, date, names, top_fams, days,
         is_baseline, db_name) in enriched:
        fname = (db_name
                 or os.path.basename(prov.get(sha, {}).get("dir", ""))
                 or sha[:12] + ".bin")

        # stats reconstructed from per-engine categories
        n_malicious = sum(1 for e in rec.values()
                          if isinstance(e, dict)
                          and e.get("category") == "malicious")
        n_suspicious = sum(1 for e in rec.values()
                           if isinstance(e, dict)
                           and e.get("category") == "suspicious")
        n_undetected = sum(1 for e in rec.values()
                           if isinstance(e, dict)
                           and e.get("category") == "undetected")

        delta = (det - baseline_det) if baseline_det is not None else None
        ws.append([
            fname, sha,
            round(100.0 * det / total, 2) if total else None,
            det, total,
            n_malicious, n_suspicious, n_undetected,
            delta if delta is not None else "",
            prov.get(sha, {}).get("variant_id",
                                  "baseline" if is_baseline else ""),
            prov.get(sha, {}).get("plan", ""),
            prov.get(sha, {}).get("n_techniques", ""),
            prov.get(sha, {}).get("subset_size", ""),
            prov.get(sha, {}).get("seed", ""),
            date, top_fams, days,
        ])
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 68
    for col in ("C", "I"):
        ws.column_dimensions[col].width = 14
    ws.column_dimensions["K"].width = 46
    ws.column_dimensions["P"].width = 46
    ws.freeze_panes = "A2"

    # ---------------- Sheet 2: Summary ----------------
    ws2 = wb.create_sheet("Summary")
    ws2.append(["Summary", ""])
    ws2["A1"].font = Font(bold=True, size=13)

    if baseline_det is not None:
        var_rows = [e for e in enriched if not e[9]]   # skip the baseline row
        dets = [e[1] for e in var_rows]
        rates = [100.0 * e[1] / e[2] if e[2] else 0 for e in var_rows]
        b_total = next((e[2] for e in enriched if e[9]), 1)
        ws2.append(["Baseline detection",
                    f"{baseline_det} ({100.0 * baseline_det / (b_total or 1):.1f}%)"])
        if dets:
            ws2.append(["Variants scanned", len(dets)])
            ws2.append(["Mean variant detections",
                        round(sum(dets) / len(dets), 2)])
            ws2.append(["Mean detection rate (%)",
                        round(sum(rates) / len(rates), 2)])
            ws2.append(["Min / Max detections", f"{min(dets)} / {max(dets)}"])
            below = sum(1 for d in dets if d < baseline_det)
            ws2.append(["Variants below baseline",
                        f"{below} ({100.0 * below / len(dets):.1f}%)"
                        if dets else "0"])
            ws2.append(["Fully undetected (0 engines)",
                        sum(1 for d in dets if d == 0)])

    # per-technique ablation: mean detection for plans containing T vs not
    ws2.append([])
    ws2.append(["Per-technique ablation", "mean detections WITH",
                "mean detections WITHOUT", "delta (pp)"])
    for c in ws2[ws2.max_row]:
        c.font = Font(bold=True)
    techniques = set()
    for p in prov.values():
        if p.get("plan"):
            techniques.update(t.strip() for t in p["plan"].split(">"))
    for t in sorted(techniques):
        with_t = [e[1] for e in enriched
                  if not e[9]
                  and t in prov.get(e[0], {}).get("plan", "")]
        without_t = [e[1] for e in enriched
                     if not e[9]
                     and t not in prov.get(e[0], {}).get("plan", "")]
        if with_t and without_t:
            mw = sum(with_t) / len(with_t)
            wo = sum(without_t) / len(without_t)
            ws2.append([t, round(mw, 2), round(wo, 2), round(wo - mw, 2)])

    wb.save(xlsx_path)
    print(f"Excel written: {xlsx_path} "
          f"({len(rows)} data row(s), "
          f"baseline={'yes' if baseline_det is not None else 'not provided'})")
    return xlsx_path

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", help="directory or single file to scan")
    ap.add_argument("--all", action="store_true",
                    help="scan all files, not just .exe/.dll")
    ap.add_argument("--report", action="store_true",
                    help="print cached results and exit")
    ap.add_argument("--excel", metavar="XLSX", nargs="?",
                    const="vt_results.xlsx",
                    help="export cached results to Excel and exit "
                         "(or after scanning, if a path is also given)")
    ap.add_argument("--baseline-sha",
                    help="sha256 of the unobfuscated rebuild (enables the "
                         "delta-vs-baseline column and Summary sheet)")
    ap.add_argument("--manifest", default="variants/manifest.json",
                    help="variants manifest for provenance join")
    args = ap.parse_args()

    # -- standalone modes: report / excel-only (no API key needed) --
    if args.report or (args.excel and not args.path):
        if args.report:
            report()
        if args.excel:
            export_excel(args.excel, args.manifest, args.baseline_sha)
        return

    # -- scan mode: API key required --
    load_dotenv()
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        sys.exit("ERROR: VT_API_KEY not set in .env")

    files = collect_files(args.path, args.all)
    if not files:
        sys.exit(f"no files found under {args.path}")
    print(f"{len(files)} file(s) queued; free tier = 4 req/min "
          f"(~{len(files) * 20 // 60} min for all-new files)\n")

    ok = failed = 0
    for i, p in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {os.path.basename(p)}")
        try:
            n = scan_file(p, api_key)
            ok += n is not None
            failed += n is None
        except SystemExit:
            raise
        except Exception as e:
            print(f"  ERROR: {e}")
            failed += 1

    print(f"\nDone: {ok} scanned/known, {failed} failed.")
    print(f"Results cached in {DB} -- run with --report / --excel any time.")
    if args.excel:
        export_excel(args.excel, args.manifest, args.baseline_sha)
    if failed:
        print("Rerun the same command later; cached files are skipped "
              "automatically and pending ones are picked up.")

if __name__ == "__main__":
    main()