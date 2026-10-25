"""
Kumo hunting harness — scope-aware scanning for bug bounty work.

Passive by default. The twelve passive modules never contact the target at all;
they read third-party data (certificate transparency, passive DNS, Shodan,
archives, breach corpora), so they are safe to run across hundreds of programs
whether or not you have confirmed a given asset is in scope.

The fifteen active modules send traffic that lands in the target's logs —
scan_nuclei alone fires over 1300 requests — so they are opt-in, per-target,
and require you to assert the asset is in scope of a program you are
authorised to test. See docs/module-classification.json for how each module was
classified (by observation, in classify_modules.py).

    python3 hunt.py --domain example.com
    python3 hunt.py --scope scope.txt --workers 4
    python3 hunt.py --domain example.com --active --in-scope
    python3 hunt.py --scope scope.txt --resume out/state.json

A scope file is one domain per line; blank lines and # comments are ignored,
and a leading "*." is stripped so HackerOne/Bugcrowd wildcard entries paste in
directly.
"""
import argparse
import concurrent.futures
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

import engine

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

# Determined by observation, not by reading the source — see classify_modules.py
PASSIVE = ["dns", "whois", "geo", "shodan", "censys", "subdomains", "brute",
           "wayback", "breachintel", "cloud_buckets", "dorks", "osint"]
ACTIVE = ["screenshot", "ssl", "headers", "wafw00f", "ports", "whatweb",
          "robots", "endpoints", "nuclei", "email_harvest", "favicon",
          "js_secrets", "content_intel", "http_inspect", "api_fuzzer"]


def load_scope(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip().lower()
            if not line:
                continue
            line = line.lstrip("*.").lstrip(".")
            # strip a scheme or path if the entry was pasted from a scope table
            line = line.replace("https://", "").replace("http://", "").split("/")[0]
            if engine.clean_domain(line):
                out.append(engine.clean_domain(line))
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


# ── reportability ranking ────────────────────────────────────────────────
# Ordered by what a triage team actually accepts. A dangling CNAME is a
# takeover; an exposed .git is source disclosure; infostealer credentials are an
# active compromise. Everything else is context, not a report.
def score(domain, res):
    findings = []

    sub = res.get("subdomains") or {}
    for r in (sub.get("resolved") or []):
        if not r.get("alive") and r.get("subdomain"):
            findings.append((40, "dangling-dns", r["subdomain"],
                             "resolves in a source but not in DNS — check for takeover"))
    for s in (sub.get("sensitive") or []):
        findings.append((15, "sensitive-subdomain", s.get("subdomain", ""),
                         "sensitive prefix, alive"))

    cb = res.get("cloud_buckets") or {}
    for b in (cb.get("found") or cb.get("buckets") or []):
        name = b.get("name") if isinstance(b, dict) else str(b)
        findings.append((60, "cloud-bucket", str(name), "bucket responded"))

    bi = res.get("breachintel") or {}
    stats = (bi.get("sources") or {}).get("hr_per_email_stats") or {}
    if stats.get("compromised"):
        findings.append((70, "infostealer", domain,
                         f"{stats['compromised']} employee address(es) in stealer logs"))

    nuc = res.get("nuclei") or {}
    for f in (nuc.get("findings") or []):
        sev = (f.get("severity") or "").lower()
        base = {"critical": 90, "high": 70, "medium": 35, "low": 15}.get(sev, 5)
        # a version-inferred finding is weaker evidence than a direct hit
        if f.get("confidence") == "version-inference":
            base = int(base * 0.5)
        findings.append((base, f"vuln-{sev}", f.get("url") or f.get("path", ""),
                         f.get("name", "")))

    ep = res.get("endpoints") or {}
    for f in (ep.get("findings") or []):
        sev = (f.get("severity") or "").lower()
        base = {"critical": 80, "high": 55, "medium": 25, "low": 10}.get(sev, 5)
        findings.append((base, f"exposure-{sev}", f.get("url", ""), f.get("name", "")))

    js = res.get("js_secrets") or {}
    for s in (js.get("secrets") or []):
        findings.append((65, "secret", str(s.get("type", "")), str(s.get("match", ""))[:60]))

    findings.sort(key=lambda x: -x[0])
    return findings


def scan_one(domain, modules, out_dir):
    t0 = time.time()
    res = {}
    for key in modules:
        entry = engine.ALL_MODULES.get(key)
        if not entry:
            continue
        try:
            res[key] = entry[1](domain)
        except Exception as e:
            res[key] = {"error": str(e)}
    ranked = score(domain, res)
    rec = {
        "domain": domain,
        "elapsed": round(time.time() - t0, 1),
        "modules": sorted(res),
        "findings": [{"score": s, "kind": k, "asset": a, "detail": d}
                     for s, k, a, d in ranked],
        "top_score": ranked[0][0] if ranked else 0,
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"{domain}.json"), "w") as f:
        json.dump({"summary": rec, "raw": res}, f, indent=1, default=str)
    return rec


def main():
    ap = argparse.ArgumentParser(description="Kumo hunting harness (passive by default)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--domain", help="single domain")
    src.add_argument("--scope", help="file of in-scope domains, one per line")
    ap.add_argument("--active", action="store_true",
                    help="also run the 15 modules that send traffic to the target")
    ap.add_argument("--in-scope", action="store_true",
                    help="assert every target is in scope of a program you may test "
                         "(required with --active)")
    ap.add_argument("--workers", type=int, default=3, help="domains in parallel")
    ap.add_argument("--out", default="hunt-out", help="output directory")
    ap.add_argument("--resume", help="state file to resume from")
    args = ap.parse_args()

    domains = [engine.clean_domain(args.domain)] if args.domain else load_scope(args.scope)
    domains = [d for d in domains if d]
    if not domains:
        print(f"{R}no valid domains{X}")
        return 2

    modules = list(PASSIVE)
    if args.active:
        if not args.in_scope:
            print(f"{R}--active needs --in-scope.{X}")
            print("  The active modules send traffic the target will log "
                  "(scan_nuclei alone makes 1300+ requests).")
            print("  Only run them against assets in scope of a program you are "
                  "authorised to test.")
            return 2
        modules += ACTIVE

    state_path = args.resume or os.path.join(args.out, "state.json")
    done = set()
    if args.resume and os.path.exists(args.resume):
        try:
            done = set(json.load(open(args.resume)).get("done", []))
        except Exception:
            pass
    todo = [d for d in domains if d not in done]

    mode = f"{R}PASSIVE + ACTIVE{X}" if args.active else f"{G}PASSIVE only{X}"
    print(f"{B}Kumo hunt{X}  {len(todo)} domain(s), {len(modules)} modules, mode: {mode}")
    if not args.active:
        print(f"  {D}passive modules never contact the target; nothing lands in its logs{X}")
    print()

    os.makedirs(args.out, exist_ok=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(scan_one, d, modules, args.out): d for d in todo}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            try:
                rec = fut.result()
            except Exception as e:
                print(f"  {R}ERR {d}: {e}{X}")
                continue
            results.append(rec)
            done.add(d)
            with open(state_path, "w") as f:
                json.dump({"done": sorted(done)}, f)
            top = rec["top_score"]
            c = R if top >= 60 else Y if top >= 30 else D
            print(f"  {c}{top:3}{X}  {d:38} {len(rec['findings']):3} finding(s)  "
                  f"{D}{rec['elapsed']}s{X}")

    # triage queue, highest value first
    results.sort(key=lambda r: -r["top_score"])
    queue = os.path.join(args.out, "triage.md")
    with open(queue, "w") as f:
        f.write("# Triage queue\n\nHighest-value first. Verify by hand before "
                "reporting anything.\n\n")
        for r in results:
            if not r["findings"]:
                continue
            f.write(f"## {r['domain']}  (top score {r['top_score']})\n\n")
            for x in r["findings"][:15]:
                f.write(f"- **{x['score']}** `{x['kind']}` — {x['asset']}  \n"
                        f"  {x['detail']}\n")
            f.write("\n")
    print(f"\n  triage queue: {queue}")
    print(f"  per-domain JSON in: {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
