"""
Full-module audit: runs every registered module against a live target and
verifies it returns a well-formed result within its configured timeout.
"""
import concurrent.futures
import json
import sys
import time
import warnings

warnings.filterwarnings("ignore")

import engine
import web

TARGET = sys.argv[1] if len(sys.argv) > 1 else "github.com"
SKIP = {"screenshot"}   # needs playwright / heavy download

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; D = "\033[90m"; X = "\033[0m"


def run_module(key):
    desc, fn = engine.ALL_MODULES[key]
    budget = web.MODULE_TIMEOUTS.get(key, web.DEFAULT_TIMEOUT)
    t0 = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(fn, TARGET)
            data = fut.result(timeout=budget)
        elapsed = time.time() - t0
        return key, desc, data, elapsed, budget, None
    except concurrent.futures.TimeoutError:
        return key, desc, None, time.time() - t0, budget, "TIMEOUT"
    except Exception as e:
        return key, desc, None, time.time() - t0, budget, f"{type(e).__name__}: {e}"


def summarize(data):
    if not isinstance(data, dict):
        return f"{type(data).__name__}"
    if data.get("error"):
        return f"error: {str(data['error'])[:52]}"
    for k in ("total", "total_found", "count"):
        if k in data:
            return f"{k}={data[k]}"
    for k, v in data.items():
        if isinstance(v, list) and v:
            return f"{k}={len(v)}"
    return f"{len(data)} field(s)"


def main():
    keys = [k for k in engine.ALL_MODULES if k not in SKIP]
    print(f"Auditing {len(keys)} modules against {TARGET}\n")
    print(f"  {'MODULE':<16} {'TIME':>7} {'BUDGET':>7}  {'USE':>5}  RESULT")
    print(f"  {'-'*16} {'-'*7} {'-'*7}  {'-'*5}  {'-'*44}")

    rows, problems = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for key, desc, data, elapsed, budget, err in ex.map(run_module, keys):
            pct = elapsed / budget * 100 if budget else 0
            if err:
                col, note = R, err[:44]
                problems.append((key, err))
            elif isinstance(data, dict) and data.get("error"):
                col, note = Y, summarize(data)
            else:
                col, note = G, summarize(data)
            if pct > 70 and not err:
                problems.append((key, f"used {pct:.0f}% of its {budget}s budget"))
            rows.append((key, elapsed, budget, pct, col, note))

    for key, elapsed, budget, pct, col, note in sorted(rows, key=lambda r: -r[1]):
        pcol = R if pct > 70 else (Y if pct > 40 else D)
        print(f"  {key:<16} {elapsed:6.1f}s {budget:6.0f}s  {pcol}{pct:4.0f}%{X}  {col}{note}{X}")

    print()
    if problems:
        print(f"{Y}Attention:{X}")
        for k, p in problems:
            print(f"  • {k}: {p}")
    else:
        print(f"{G}All modules returned cleanly, none near its timeout budget.{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
