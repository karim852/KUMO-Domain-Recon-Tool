"""
Mine recently-added *unauthenticated / anonymous access* nuclei templates and
turn them into Kumo rules.

This is the same pipeline as mine_templates.py -> gen_rules.py, narrowed to one
family and one time window:

    python3 mine_unauth.py --nuclei /path/to/nuclei-templates --since 2025-01-01
    python3 validate_rules.py          # decoy gate, writes /tmp/validated_rules.json

Two deliberate differences from gen_rules.py:

  * gen_rules.PRIORITY is NOT applied. That filter keeps the bulk import to
    well-known product families; here the selection criterion is already
    narrow (unauthenticated access), so requiring a known family would throw
    away most of the new API-surface exposures.

  * WordPress `readme.txt` probes are dropped. They are version disclosure
    rather than unauthenticated access, and they fire on essentially every
    WordPress site, which is exactly the kind of noise the false-positive
    layer exists to avoid.

Every other guarantee is inherited: GET-only, single path, real word evidence,
status matcher paired with an evidence matcher under `matchers_condition: and`.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

import gen_rules
import mine_templates

UNAUTH = re.compile(r"unauth|anonymous", re.I)

# Version-disclosure probes masquerading as access checks.
WP_README = re.compile(r"/wp-content/plugins/[^/]+/readme\.txt|/readme\.txt$", re.I)

DATE_CACHE = ".nuclei-added-dates.json"


def template_dates(nuclei_root, cache=DATE_CACHE):
    """First-commit date per template path. Cached — the history walk over
    ~75k commits is slow, and the answer only changes when you re-pull."""
    if os.path.exists(cache):
        try:
            return json.load(open(cache))
        except Exception:
            pass
    print("  walking template history (slow, cached afterwards)…", flush=True)
    out = subprocess.run(
        ["git", "log", "--diff-filter=A", "--name-only",
         "--format=@%ad", "--date=short", "--", "http/"],
        cwd=nuclei_root, capture_output=True, text=True, timeout=1800).stdout
    dates, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@"):
            cur = line[1:]
        elif line.endswith(".yaml") and cur:
            dates[line] = cur          # newest-first walk, so last write = true add
    json.dump(dates, open(cache, "w"))
    return dates


def existing_rules():
    """Paths and ids Kumo already ships, so we only ever propose new ground."""
    import ast
    tree = ast.parse(open("engine.py", encoding="utf-8").read())
    paths, ids = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in ("VULN_RULES", "VULN_RULES_EXTENDED"):
                    for r in ast.literal_eval(node.value):
                        paths.add(r["path"])
                        ids.add(str(r.get("id", "")).lower())
    return paths, ids


def to_rule(t):
    """gen_rules.to_rule without the PRIORITY family gate."""
    path = t["paths"][0]
    if not path.startswith("/") or gen_rules.SKIP_PATH.search(path) or len(path) > 90:
        return None
    words = gen_rules.clean_words(t["words"])
    if not words:
        return None

    sev = t["severity"] if t["severity"] in gen_rules.SEV_RANK else "info"
    statuses = t["statuses"] or [200]
    if 200 not in statuses:
        statuses = sorted(set(statuses + [200]))

    return {
        "id": t["id"][:60],
        "name": t["name"][:80],
        "severity": sev,
        "path": path,
        "matchers_condition": "and",
        "description": f"{t['name'][:110]} (ported from nuclei template {t['file']})",
        "matchers": [
            {"type": "status", "status": statuses[:4]},
            {"type": "word", "part": "all", "words": words[:8], "condition": "or"},
        ],
        "origin": "nuclei-unauth",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nuclei", required=True, help="Path to a nuclei-templates clone")
    ap.add_argument("--since", default="2025-01-01", help="Only templates added on/after this date")
    ap.add_argument("--keep-wp-readme", action="store_true",
                    help="Keep WordPress readme.txt version probes (off by default)")
    ap.add_argument("-o", "--output", default="/tmp/generated_rules.json")
    args = ap.parse_args()

    root = os.path.abspath(args.nuclei)
    mine_templates.ROOT = root

    print(f"nuclei-templates: {root}")
    dates = template_dates(root)
    print(f"  dated templates: {len(dates)}")

    have_paths, have_ids = existing_rules()
    print(f"  kumo already covers: {len(have_paths)} paths / {len(have_ids)} ids")

    stats = defaultdict(int)
    rules, seen_paths, seen_ids = [], set(), set()

    for dirpath, _, files in os.walk(os.path.join(root, "http")):
        for fn in files:
            if not fn.endswith(".yaml"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)

            t = mine_templates.parse(full)
            if not t:
                continue
            stats["parsed"] += 1

            if not UNAUTH.search(f"{t['id']} {t['name']} {t['tags']}"):
                continue
            stats["unauth"] += 1

            added = dates.get(rel)
            if not added or added < args.since:
                stats["too old / undated"] += 1
                continue
            stats["in window"] += 1

            if t["methods"] != ["GET"] or len(t["paths"]) != 1:
                stats["not drop-in (POST/multi-path)"] += 1
                continue

            if not args.keep_wp_readme and WP_README.search(t["paths"][0]):
                stats["wordpress readme.txt dropped"] += 1
                continue

            if t["paths"][0] in have_paths or t["id"].lower() in have_ids:
                stats["already covered"] += 1
                continue

            r = to_rule(t)
            if not r:
                stats["no usable word evidence"] += 1
                continue
            if r["path"] in seen_paths or r["id"] in seen_ids:
                stats["duplicate"] += 1
                continue

            r["added"] = added
            seen_paths.add(r["path"])
            seen_ids.add(r["id"])
            rules.append(r)

    rules.sort(key=lambda r: (gen_rules.SEV_RANK.get(r["severity"], 9), r["path"]))

    print("\nfunnel:")
    for k in ["parsed", "unauth", "too old / undated", "in window",
              "not drop-in (POST/multi-path)", "wordpress readme.txt dropped",
              "already covered", "no usable word evidence", "duplicate"]:
        if stats.get(k):
            print(f"  {stats[k]:>6}  {k}")

    bysev = defaultdict(int)
    for r in rules:
        bysev[r["severity"]] += 1
    print(f"\ngenerated {len(rules)} rules:",
          dict(sorted(bysev.items(), key=lambda kv: gen_rules.SEV_RANK[kv[0]])))

    json.dump(rules, open(args.output, "w"), indent=1)
    print(f"wrote {args.output}")
    print("\nnext:  python3 validate_rules.py     # decoy gate")

    for r in rules[:10]:
        print(f"  [{r['severity']:<8}] {r['added']}  {r['path'][:44]:<44} {r['name'][:38]}")


if __name__ == "__main__":
    main()
