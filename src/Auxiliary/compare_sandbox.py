#!/usr/bin/env python3
"""Submit two samples to CAPE, wait for reports, print a comparison.

Also computes a normalized Longest Common Subsequence (LCS) score between
the two samples' API call sequences, following the Functionality
Preservation Metric from LLMalMorph (arXiv:2507.09411):

    lcs_hat(ref, cand) = LCS(API(ref), API(cand)) / len(API(ref))

`ref` is the ORIGINAL binary's call sequence (the denominator); `cand` is
the decompiled/recompiled binary being checked against it. 1.0 means every
API call in the original, in order, also shows up (possibly with extra
calls interleaved) in the candidate's trace. Swapping ref/cand changes the
score, since the denominator changes -- always pass the original first.

Every pair tested -- whether via a single-pair call or via --manifest --
gets one row appended to <project root>/Results/comparisons.xlsx, written
by the reporting.ComparisonReport object (reporting/excel_report.py).
"<project root>" is this script's parent's parent directory, matching the
"../Results" layout: this script is expected to live one directory below
the project root, with `reporting/` and `Results/` as siblings at that
root. Override with --results-xlsx if your layout differs.

Usage:
    python compare_sandbox.py original.exe recompiled.exe   # single pair
    python compare_sandbox.py --manifest pairs.csv           # batch

pairs.csv: one "original_path,candidate_path" line per pair, no header.
Batch mode also writes a per-pair summary to --summary-out (default
lcs_summary.csv) with the LCS scores alongside raw/collapsed call counts
-- that's unchanged and independent of the Excel log.
"""
import argparse
import csv
import sys, time, json, requests
import re
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

NOISE_APIS = {"NtTestAlert", "LdrpCallInitRoutine", "RtlUserThreadStart"}  # loader noise, edit freely
HEX = re.compile(r"0x[0-9a-fA-F]+")

CAPE = "http://127.0.0.1:8000/apiv2"
TOKEN = ""
HEADERS = {"Authorization": f"Token {TOKEN}"} if TOKEN else {}
OPTIONS = {"timeout": 60, "machine": "", "package": ""}  # tweak as needed

# LCS cost control: the DP below is O(n*m) time / O(min(n,m)) space.
# Above this many (n*m) cells it gets slow in pure Python, so longer
# sequences get truncated to their first K calls each -- same idea as the
# existing [:5000] cap already used for the SequenceMatcher ratio below.
MAX_LCS_CELLS = 25_000_000

# --- reporting (Results/comparisons.xlsx) -----------------------------
# This script is assumed to live one directory below the project root,
# e.g. GhidraHush/<some-subfolder>/compare_sandbox.py, with `reporting/`
# and `Results/` as siblings directly under GhidraHush/. Resolved from
# __file__ so it works regardless of the current working directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_XLSX_PATH = PROJECT_ROOT / "Results" / "comparisons.xlsx"
sys.path.insert(0, str(PROJECT_ROOT))
from reports import ComparisonReport  # noqa: E402  (needs sys.path set first)

REPORT = None  # set in main() once --results-xlsx (or the default) is known


def submit(path):
    with open(path, "rb") as f:
        r = requests.post(f"{CAPE}/tasks/create/file/",
                          files={"file": (path.split("/")[-1], f)},
                          data=OPTIONS, headers=HEADERS)
    r.raise_for_status()
    j = r.json()
    if j.get("error"):
        raise RuntimeError(j)
    return j["data"]["task_ids"][0]


def wait(task_id, poll=10, limit=1800):
    start = time.time()
    while time.time() - start < limit:
        r = requests.get(f"{CAPE}/tasks/status/{task_id}/", headers=HEADERS)
        status = r.json().get("data")
        print(f"[task {task_id}] {status}", file=sys.stderr)
        if status == "reported":
            return
        if status and status.startswith("failed"):
            raise RuntimeError(f"task {task_id} {status}")
        time.sleep(poll)
    raise TimeoutError(task_id)


def report(task_id):
    r = requests.get(f"{CAPE}/tasks/get/report/{task_id}/json/", headers=HEADERS)
    r.raise_for_status()
    return r.json()


def features(rep):
    """Flatten a report into comparable sets."""
    summ = rep.get("behavior", {}).get("summary", {})
    net = rep.get("network", {})
    f = {
        "signatures": {s["name"] for s in rep.get("signatures", [])},
        "mutexes": set(summ.get("mutexes", [])),
        "files_touched": set(summ.get("files", [])),
        "files_written": set(summ.get("write_files", [])),
        "regkeys_written": set(summ.get("write_keys", [])),
        "commands": set(summ.get("executed_commands", [])),
        "resolved_apis": set(summ.get("resolved_apis", [])),
        "domains": {d.get("domain") for d in net.get("domains", [])},
        "hosts": {h.get("ip") for h in net.get("hosts", [])},
        "http_uris": {h.get("uri") for h in net.get("http", [])},
        "dropped_sha256": {d.get("sha256") for d in rep.get("dropped", [])},
        "cape_payloads": {p.get("sha256") for p in rep.get("CAPE", {}).get("payloads", [])
                          if isinstance(p, dict)},
    }
    # imports location differs between CAPE versions
    pe = rep.get("target", {}).get("file", {}).get("pe") or rep.get("static", {}).get("pe", {})
    imps = set()
    for dll in (pe.get("imports") or {}).values() if isinstance(pe.get("imports"), dict) else pe.get("imports", []) or []:
        for i in dll.get("imports", []):
            imps.add(f'{dll.get("dll")}!{i.get("name")}')
    f["pe_imports"] = imps
    return f


def compare(a, b):
    out = {}
    for k in a:
        out[k] = {
            "common": sorted(x for x in a[k] & b[k] if x),
            "only_A": sorted(x for x in a[k] - b[k] if x),
            "only_B": sorted(x for x in b[k] - a[k] if x),
        }
    return out


def sample_names(rep):
    n = rep.get("target", {}).get("file", {}).get("name", "")
    return sorted({n, n.rsplit(".", 1)[0]} - {""}, key=len, reverse=True)


def normalize(value, names):
    s = str(value)
    for n in names:
        s = re.sub(re.escape(n), "<SAMPLE>", s, flags=re.I)
    s = re.sub(r"(?i)\\Users\\[^\\]+", r"\\Users\\<USER>", s)
    return HEX.sub("<HEX>", s)


def call_features(rep):
    """Flatten a report's behavior section into API-call-level features.

    seq      -- API names in call order, consecutive repeats collapsed
                (what the SequenceMatcher ratio below already used)
    raw_seq  -- API names in call order, NOT collapsed; this is what
                LLMalMorph's normalized-LCS metric is defined over

    NOTE: this merges all processes in report order. For malware that
    spawns children or injects, that's a simplification -- it doesn't
    reconstruct true cross-process temporal order. If that matters for
    your evaluation, score per matched process_name instead of merging.
    """
    names = sample_names(rep)
    apis, cats, args, seq, raw_seq, procs = Counter(), Counter(), set(), [], [], set()
    for p in rep.get("behavior", {}).get("processes", []):
        procs.add(normalize(p.get("process_name", ""), names))
        for c in p.get("calls", []):
            api = c.get("api")
            if not api or api in NOISE_APIS:
                continue
            apis[api] += 1
            cats[c.get("category", "?")] += 1
            raw_seq.append(api)
            if not seq or seq[-1] != api:          # collapse repeats
                seq.append(api)
            for a in c.get("arguments", []):
                v = a.get("value")
                if isinstance(v, str) and len(v) > 3 and not HEX.fullmatch(v):
                    args.add(f'{api}.{a.get("name")}={normalize(v, names)}')
    return {"apis": apis, "categories": cats, "args": args,
            "seq": seq, "raw_seq": raw_seq, "procs": procs}


def print_call_diff(ca, cb, top=30):
    print(f"\n== API calls: {sum(ca['apis'].values())} in A, {sum(cb['apis'].values())} in B")
    rows = sorted(((k, ca["apis"][k], cb["apis"][k]) for k in set(ca["apis"]) | set(cb["apis"])),
                  key=lambda r: abs(r[1] - r[2]), reverse=True)
    print(f"{'API':38}{'A':>7}{'B':>7}{'delta':>8}")
    for k, a, b in [r for r in rows if r[1] != r[2]][:top]:
        print(f"{k:38}{a:>7}{b:>7}{b - a:>+8}")
    print("\nAPIs only in A:", sorted(set(ca["apis"]) - set(cb["apis"])))
    print("APIs only in B:", sorted(set(cb["apis"]) - set(ca["apis"])))
    print("Category counts A:", dict(ca["categories"]))
    print("Category counts B:", dict(cb["categories"]))
    # NOTE: SequenceMatcher.ratio() is Ratcliff-Obershelp similarity
    # (longest matching *blocks*, recursively), a different algorithm from
    # the LCS below -- it will generally give a different number. Kept here
    # as a cheap secondary similarity check, not as the paper-comparable metric.
    sim = SequenceMatcher(None, ca["seq"][:5000], cb["seq"][:5000], autojunk=False).ratio()
    print(f"\nAPI sequence similarity (difflib, collapsed, capped@5000): {sim:.1%}")
    for label, x, y in (("A", ca["args"], cb["args"]), ("B", cb["args"], ca["args"])):
        only = sorted(x - y)
        print(f"\n== call arguments only in {label} ({len(only)}), first 40:")
        for line in only[:40]:
            print("  ", line)


# ---------------------------------------------------------------------------
# LCS-based Functionality Preservation Metric (LLMalMorph, arXiv:2507.09411)
# ---------------------------------------------------------------------------

def lcs_length(a, b):
    """Exact length of the longest common SUBSEQUENCE of a and b (order preserved,
    gaps allowed, no reordering credit).

    Bit-parallel algorithm (Allison-Dix / Crochemore et al. 2001): one Python big
    integer holds a whole DP row, so the cost is O(len(a) * len(b) / word_size)
    instead of O(len(a) * len(b)) interpreter steps. That makes full-length
    traces (tens of thousands of API calls) cheap, so they no longer have to be
    truncated -- see bounded_lcs_length below for why truncation broke the metric.
    """
    if len(a) > len(b):
        a, b = b, a
    n = len(a)
    if n == 0:
        return 0
    masks = {}
    for i, x in enumerate(a):
        masks[x] = masks.get(x, 0) | (1 << i)
    full = (1 << n) - 1
    v = full
    for y in b:
        m = masks.get(y, 0)
        u = v & m
        v = ((v + u) | (v & ~m)) & full
    return n - bin(v).count("1")


def bounded_lcs_length(a, b, max_cells=MAX_LCS_CELLS):
    """Kept for compatibility. The old version truncated both sequences once
    len(a)*len(b) > max_cells but lcs_hat still divided by the UNTRUNCATED
    len(ref): two identical 20,000-call traces scored 0.25 instead of 1.0. The
    bit-parallel lcs_length is fast enough that truncation is no longer needed."""
    return lcs_length(a, b)


def lcs_hat(seq_ref, seq_cand):
    """Normalized LCS score: LCS(ref, cand) / len(ref).
    seq_ref MUST be the original/reference binary's sequence -- it's the
    denominator, so swapping ref and cand changes the score."""
    if not seq_ref:
        return 0.0
    return bounded_lcs_length(seq_ref, seq_cand) / len(seq_ref)


def print_lcs(c_ref, c_cand):
    print(f"\n== Functionality Preservation (LCS), reference=original, candidate=recompiled")
    scores = {}
    for field, tag, key in (("raw_seq", "raw", "lcs_raw"), ("seq", "collapsed", "lcs_collapsed")):
        score = lcs_hat(c_ref[field], c_cand[field])
        scores[key] = score
        print(f"  lcs_hat [{tag:9}] = {score:.4f}  "
              f"(ref len={len(c_ref[field])}, cand len={len(c_cand[field])})")
    return scores


# ---------------------------------------------------------------------------

def process_pair(path_ref, path_cand):
    """Submit, wait, fetch, diff and LCS-score one (original, candidate) pair.
    Also appends one row to Results/comparisons.xlsx via REPORT."""
    t_ref, t_cand = submit(path_ref), submit(path_cand)
    print(f"submitted: original={t_ref} ({path_ref})  candidate={t_cand} ({path_cand})", file=sys.stderr)
    wait(t_ref); wait(t_cand)
    r_ref, r_cand = report(t_ref), report(t_cand)

    json.dump(r_ref, open(f"report_{t_ref}.json", "w"))
    json.dump(r_cand, open(f"report_{t_cand}.json", "w"))

    result = compare(features(r_ref), features(r_cand))
    # per-pair filename -- the original script's "comparison.json" would
    # overwrite itself across pairs in batch mode
    json.dump(result, open(f"comparison_{t_ref}_{t_cand}.json", "w"), indent=2)
    for k, v in result.items():
        print(f"\n== {k}: {len(v['common'])} common, "
              f"{len(v['only_A'])} only in original, {len(v['only_B'])} only in candidate")

    c_ref, c_cand = call_features(r_ref), call_features(r_cand)
    print_call_diff(c_ref, c_cand)
    lcs_scores = print_lcs(c_ref, c_cand)

    row = {
        "original_path": path_ref, "candidate_path": path_cand,
        "task_original": t_ref, "task_candidate": t_cand,
        "api_calls_original": sum(c_ref["apis"].values()),
        "api_calls_candidate": sum(c_cand["apis"].values()),
        **lcs_scores,
    }

    written_row = REPORT.add_result(row)
    print(f"[xlsx] appended row {written_row} to {REPORT.path}", file=sys.stderr)

    return row


def main():
    global REPORT

    ap = argparse.ArgumentParser()
    ap.add_argument("sample_a", nargs="?", help="original binary")
    ap.add_argument("sample_b", nargs="?", help="candidate (decompiled/recompiled) binary")
    ap.add_argument("--manifest", help="CSV, one 'original_path,candidate_path' row per pair; "
                                        "runs every pair and writes a summary CSV")
    ap.add_argument("--summary-out", default="lcs_summary.csv")
    ap.add_argument("--results-xlsx", default=str(DEFAULT_XLSX_PATH),
                     help=f"path to the running Excel log (default: {DEFAULT_XLSX_PATH})")
    args = ap.parse_args()

    REPORT = ComparisonReport(args.results_xlsx)

    if args.manifest:
        rows = []
        with open(args.manifest, newline="") as f:
            for row in csv.reader(f):
                if not row or row[0].startswith("#"):
                    continue
                path_ref, path_cand = row[0].strip(), row[1].strip()
                print(f"\n{'='*70}\n{path_ref}  vs  {path_cand}\n{'='*70}")
                try:
                    rows.append(process_pair(path_ref, path_cand))
                except Exception as e:
                    print(f"[!] pair failed: {path_ref} / {path_cand}: {e}", file=sys.stderr)
                    rows.append({"original_path": path_ref, "candidate_path": path_cand,
                                 "error": str(e)})
        if rows:
            with open(args.summary_out, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r}))
                writer.writeheader()
                writer.writerows(rows)
            print(f"\nwrote {len(rows)} pair(s) to {args.summary_out}")
    else:
        if not (args.sample_a and args.sample_b):
            ap.error("give two paths (original, candidate), or --manifest pairs.csv")
        process_pair(args.sample_a, args.sample_b)


if __name__ == "__main__":
    main()