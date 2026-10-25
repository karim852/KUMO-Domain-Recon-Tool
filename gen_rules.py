"""
Convert mined nuclei templates into Kumo VULN_RULES entries.

Selection is deliberately conservative — only templates that give us genuine
evidence to match on, following nuclei's own guidance that a rule must pair
product identification with vulnerability evidence and never rely on a bare
status code.
"""
import json
import re
from collections import defaultdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Words too generic to be evidence on their own (nuclei's own "BAD matcher" list)
GENERIC = {
    "admin", "login", "password", "username", "error", "true", "false", "index",
    "html", "user", "users", "config", "test", "home", "page", "welcome", "search",
    "submit", "form", "name", "title", "email", "sign in", "log in", "dashboard",
    "settings", "status", "version", "data", "id", "type", "value", "server",
    "content", "text", "code", "message", "success", "ok", "yes", "no", "null",
}

# Families we most want covered (CMS, devops, panels, data stores)
PRIORITY = re.compile(
    r'drupal|joomla|magento|typo3|sitecore|umbraco|moodle|prestashop|opencart|'
    r'sharepoint|confluence|jira|bitbucket|zabbix|nagios|jupyter|airflow|consul|'
    r'vault|etcd|minio|harbor|rancher|argocd|keycloak|nextcloud|owncloud|strapi|'
    r'ghost|django|symfony|coldfusion|weblogic|tomcat|struts|spring|graphql|'
    r'swagger|openapi|kubernetes|docker|redis|mongo|elastic|couchdb|solr|rabbitmq|'
    r'kibana|grafana|prometheus|jenkins|gitlab|sonarqube|nexus|artifactory|'
    r'phpmyadmin|adminer|wordpress|laravel|env|backup|dump|credential|token|'
    r'secret|key|config|log|debug|actuator|metrics|storage|s3|firebase|'
    r'traefik|portainer|kong|nacos|apollo|druid|zipkin|eureka|hadoop|zookeeper',
    re.I)

SKIP_PATH = re.compile(r'\{\{|\$|\.\.|%2e|\*|\?.*=.*&.*=', re.I)

# Paths whose last segment is nothing but percent-escapes or punctuation are
# encoding probes, not resources (nuclei's "/%c0"). Ported as a rule they claim
# a finding from whatever the server happens to return for a junk URL.
JUNK_BASENAME = re.compile(r'^(?:(?:%[0-9a-f]{2})+|[^a-z0-9]+)$', re.I)


def _norm(w):
    """Compare words without their JSON quoting, so '"title":' == 'title'."""
    return (w or "").strip().strip('"\'`:,;=<>[](){} \t').lower()


def clean_words(words):
    out = []
    for w in words:
        w = w.strip()
        if not w or len(w) < 4 or len(w) > 80:
            continue
        # Quoting used to smuggle generic tokens past this filter: '"title"'
        # is not in GENERIC, but 'title' is — and that is the same evidence.
        if _norm(w) in GENERIC:
            continue
        if w.startswith(("{{", "$")) or "{{" in w:
            continue
        out.append(w)
    # de-dup, keep order
    seen, uniq = set(), []
    for w in out:
        k = _norm(w)
        if k not in seen:
            seen.add(k)
            uniq.append(w)
    return uniq


def to_rule(t):
    path = t["paths"][0]
    if not path.startswith("/") or SKIP_PATH.search(path) or len(path) > 90:
        return None
    base = path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    if base and JUNK_BASENAME.match(base):
        return None

    # Only word matchers are ported. Regexes extracted by a lightweight YAML
    # reader proved unreliable — adjacent matcher blocks leaked in ("type: status")
    # and YAML escaping turned \\d into a literal backslash — so a rule must
    # stand on its word evidence alone or not be ported at all.
    words = clean_words(t["words"])
    if not words:
        return None
    regexes = []

    blob = f"{t['id']} {t['tags']} {path} {t['name']}"
    if not PRIORITY.search(blob):
        return None

    sev = t["severity"] if t["severity"] in SEV_RANK else "info"
    # Panels and tech-detections are informational unless the template says worse
    if "exposed-panels" in t["file"] and sev in ("unknown",):
        sev = "info"

    matchers = []
    statuses = t["statuses"] or [200]
    if 200 not in statuses:
        statuses = sorted(set(statuses + [200]))
    matchers.append({"type": "status", "status": statuses[:4]})

    # Product/vulnerability evidence. Each of the template's word blocks becomes
    # its own matcher, keeping the block's own condition, because nuclei ANDs
    # separate blocks together. Merging them into one OR list (the old behaviour)
    # let a single generic token satisfy a rule that was written to require
    # several — by far the biggest source of false positives in the playbook.
    blocks = []
    for blk in (t.get("word_blocks") or []):
        bw = clean_words(blk.get("words") or [])
        if bw:
            blocks.append({"type": "word", "part": "all", "words": bw[:8],
                           "condition": blk.get("condition", "or")})
    if blocks:
        matchers += blocks[:3]
    elif words:
        matchers.append({"type": "word", "part": "all", "words": words[:8],
                         "condition": "or"})

    # A rule must rest on at least one specific word; a block of pure web
    # vocabulary proves nothing. (engine._is_strong_evidence enforces the same
    # floor at scan time for rules already shipped.)
    if not any(any(_norm(w) not in GENERIC and len(_norm(w)) >= 4 for w in m["words"])
               for m in matchers if m["type"] == "word"):
        return None

    # A raw-file exposure must not be satisfiable by a rendered HTML page.
    if re.search(r'/\.[^/]+$|\.(env|ya?ml|json|ini|conf|cfg|properties|sql|bak|log|pem|key|npmrc|s3cfg|toml)$',
                 path, re.I):
        matchers.append({"type": "dsl", "dsl": ["not_html"]})

    return {
        "id": t["id"][:60],
        "name": t["name"][:80],
        "severity": sev,
        "path": path,
        "matchers_condition": "and",
        "description": f"{t['name'][:110]} (ported from nuclei template {t['file']})",
        "matchers": matchers,
        "origin": "nuclei",
    }


def main():
    templates = json.load(open("/tmp/templates.json"))
    rules, seen_paths, seen_ids = [], set(), set()

    # highest severity first, then templates with more evidence words
    templates.sort(key=lambda t: (SEV_RANK.get(t["severity"], 9), -len(t["words"])))

    for t in templates:
        r = to_rule(t)
        if not r:
            continue
        if r["path"] in seen_paths or r["id"] in seen_ids:
            continue
        seen_paths.add(r["path"])
        seen_ids.add(r["id"])
        rules.append(r)

    print(f"generated {len(rules)} rules")
    bysev = defaultdict(int)
    for r in rules:
        bysev[r["severity"]] += 1
    print("by severity:", dict(sorted(bysev.items(), key=lambda kv: SEV_RANK[kv[0]])))

    json.dump(rules, open("/tmp/generated_rules.json", "w"), indent=1)
    print("wrote /tmp/generated_rules.json")

    for r in rules[:12]:
        print(f"  [{r['severity']:<8}] {r['path']:<42} {r['name'][:44]}")


if __name__ == "__main__":
    main()
