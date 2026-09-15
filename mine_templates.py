"""
Mine the official nuclei-templates repo for high-value sensitive endpoints
and their matcher words, so Kumo's path list and rule playbook are grounded in
real templates rather than guesswork.
"""
import json
import os
import re
import sys
from collections import defaultdict

ROOT = "/tmp/nt"
DIRS = ["http/exposures", "http/exposed-panels", "http/misconfiguration",
        "http/technologies", "http/default-logins"]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def parse(path):
    """Very small YAML subset parser tuned to nuclei template shape."""
    try:
        txt = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return None
    if "{{BaseURL}}" not in txt:
        return None

    tid = (re.search(r'^id:\s*(\S+)', txt, re.M) or [None, os.path.basename(path)[:-5]])[1]
    name = (re.search(r'^\s*name:\s*(.+)$', txt, re.M) or [None, tid])[1].strip().strip('"\'')
    sev = (re.search(r'^\s*severity:\s*(\w+)', txt, re.M) or [None, "info"])[1].lower()
    tags = (re.search(r'^\s*tags:\s*(.+)$', txt, re.M) or [None, ""])[1].strip()

    # paths
    paths = []
    for m in re.finditer(r'"\{\{BaseURL\}\}([^"]*)"', txt):
        p = m.group(1)
        if p and "{{" not in p:
            paths.append(p)
    if not paths:
        return None

    # request methods used
    methods = set(re.findall(r'^\s*-?\s*method:\s*(\w+)', txt, re.M)) or {"GET"}

    # matcher words (body/all) — the product/vuln indicators.
    # A words: list ends as soon as the next matcher item begins ("- type: ..."),
    # so any captured entry containing a YAML key is a parser leak and dropped.
    YAML_LEAK = re.compile(r'^(type|part|condition|status|name|severity|method|'
                           r'matchers|words|regex|dsl|path|id|tags|encoding|'
                           r'case-insensitive|negative|internal|group)\s*:', re.I)
    CT_NOISE = {"application/json", "application/html", "text/html", "text/plain",
                "application/xml", "application/octet-stream", "text/xml"}
    words = []
    for blk in re.finditer(r'words:\s*\n((?:[ \t]*-[ \t]*.+\n)+)', txt):
        for line in blk.group(1).splitlines():
            m = re.match(r'[ \t]*-[ \t]*(?:"([^"]*)"|\'([^\']*)\'|(.+))', line)
            if not m:
                continue
            val = (m.group(1) or m.group(2) or m.group(3) or "").strip()
            if not val or len(val) >= 90:
                continue
            if YAML_LEAK.match(val):
                break          # next matcher started — stop this words list
            if val.lower() in CT_NOISE:
                continue       # content-type strings match almost anything
            words.append(val)

    statuses = []
    for blk in re.finditer(r'status:\s*\n((?:\s*-\s*\d+\n)+)', txt):
        statuses += [int(x) for x in re.findall(r'-\s*(\d+)', blk.group(1))]

    regexes = []
    for blk in re.finditer(r'regex:\s*\n((?:\s*-\s*.+\n)+)', txt):
        for r_ in re.findall(r'-\s*(?:"([^"]*)"|\'([^\']*)\'|(.+))', blk.group(1)):
            val = (r_[0] or r_[1] or r_[2]).strip()
            if val:
                regexes.append(val)

    cond = (re.search(r'^\s*matchers-condition:\s*(\w+)', txt, re.M) or [None, "or"])[1]

    return {
        "id": tid, "name": name, "severity": sev, "tags": tags,
        "paths": paths[:6], "methods": sorted(methods),
        "words": words[:14], "statuses": sorted(set(statuses))[:6],
        "regexes": regexes[:4], "matchers_condition": cond,
        "file": os.path.relpath(path, ROOT),
    }


def main():
    out = []
    for d in DIRS:
        base = os.path.join(ROOT, d)
        for dirpath, _, files in os.walk(base):
            for f in files:
                if f.endswith(".yaml"):
                    t = parse(os.path.join(dirpath, f))
                    if t:
                        out.append(t)

    print(f"parsed {len(out)} usable templates")

    # GET-only, single-path, with real matcher evidence — safest to port
    usable = [t for t in out
              if t["methods"] == ["GET"] and (t["words"] or t["regexes"])]
    print(f"GET-only with matchers: {len(usable)}")

    by_sev = defaultdict(int)
    for t in usable:
        by_sev[t["severity"]] += 1
    print("by severity:", dict(sorted(by_sev.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))))

    # unique paths
    paths = defaultdict(list)
    for t in usable:
        for p in t["paths"]:
            paths[p].append(t)
    print(f"unique paths: {len(paths)}")

    json.dump(usable, open("/tmp/templates.json", "w"), indent=0)
    print("wrote /tmp/templates.json")

    # show what families we can now cover
    fams = ["drupal", "joomla", "magento", "typo3", "sitecore", "umbraco", "moodle",
            "prestashop", "opencart", "sharepoint", "confluence", "jira", "zabbix",
            "nagios", "jupyter", "airflow", "consul", "vault", "etcd", "minio",
            "harbor", "rancher", "argocd", "keycloak", "nextcloud", "owncloud",
            "strapi", "ghost", "django", "symfony", "coldfusion", "weblogic",
            "tomcat", "struts", "spring", "graphql", "swagger", "kubernetes",
            "docker", "redis", "mongo", "elastic", "couchdb", "solr", "rabbitmq"]
    blob = " ".join((t["id"] + " " + t["tags"] + " " + " ".join(t["paths"])).lower() for t in usable)
    hits = {f: blob.count(f) for f in fams}
    print("\nfamily coverage available in templates:")
    print({k: v for k, v in sorted(hits.items(), key=lambda kv: -kv[1]) if v})


if __name__ == "__main__":
    main()
