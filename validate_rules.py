"""
Select a high-value subset of the auto-generated nuclei-derived rules and
validate each one against decoy responses. Any rule that fires on a decoy is
discarded — a rule that cannot survive a soft-404 is worse than no rule.
"""
import json
import re
import sys

import engine

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Families worth spending a request on for low/info severity rules
KEEP_LOW = re.compile(
    r'drupal|joomla|magento|typo3|sitecore|umbraco|moodle|prestashop|opencart|'
    r'sharepoint|confluence|jira|zabbix|nagios|jupyter|airflow|consul|vault|etcd|'
    r'minio|harbor|rancher|argocd|keycloak|nextcloud|owncloud|strapi|ghost|django|'
    r'symfony|coldfusion|weblogic|tomcat|struts|spring|actuator|graphql|swagger|'
    r'openapi|kubernetes|docker|redis|mongo|elastic|couchdb|solr|rabbitmq|kibana|'
    r'grafana|prometheus|jenkins|gitlab|sonarqube|nexus|artifactory|phpmyadmin|'
    r'adminer|wordpress|laravel|traefik|portainer|kong|nacos|druid|eureka|'
    r'zookeeper|hadoop|env|backup|dump|credential|token|secret|config|debug',
    re.I)

MAX_RULES = 320


class R:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self.content = body.encode() if isinstance(body, str) else body
        self.text = body if isinstance(body, str) else body.decode("utf-8", "ignore")
        self.headers = headers or {}


HTML = {"Content-Type": "text/html; charset=utf-8"}
JSON_H = {"Content-Type": "application/json"}

# Decoys: none of these may ever satisfy a rule
DECOYS = {
    "soft-404": R(200, "<!doctype html><html><head><title>404 - Page Not Found</title></head>"
                       "<body><h1>Page Not Found</h1><p>Sorry, that page does not exist. "
                       "Try our search or go back home.</p>" + "x" * 900 + "</body></html>", HTML),
    "waf-403": R(403, "<!doctype html><html><head><title>403 Forbidden</title></head><body>"
                      "<h1>Access Denied</h1>Request blocked by security policy."
                      + "y" * 1100 + "</body></html>", HTML),
    "marketing-home": R(200, "<!doctype html><html><head><title>Acme Store — Buy Online</title>"
                             "</head><body><nav>Home Products About Contact Login Admin Panel</nav>"
                             "<h1>Welcome to Acme</h1><p>Your account, settings, dashboard, users, "
                             "config, status, version, data and services in one place. "
                             "Powered by our platform. Sign in to manage orders.</p>"
                             + "z" * 2500 + "</body></html>", HTML),
    "spa-shell": R(200, "<!doctype html><html><head><title>App</title>"
                        "<script src='/static/js/main.js'></script></head>"
                        "<body><div id='root'></div></body></html>", HTML),
    "empty-200": R(200, "", HTML),
    "json-error": R(200, '{"error":"not_found","message":"resource does not exist","status":404}', JSON_H),
    "redirect": R(302, "", {"Location": "https://example.com/login"}),
    "generic-login": R(200, "<!doctype html><html><head><title>Sign in</title></head><body>"
                            "<form method=post><input name=username><input name=password "
                            "type=password><button>Log in</button></form></body></html>", HTML),
}


def main():
    gen = json.load(open("/tmp/generated_rules.json"))

    # ── selection ──
    picked = []
    for r in sorted(gen, key=lambda x: (SEV_RANK.get(x["severity"], 9), x["path"])):
        sev = r["severity"]
        if sev in ("critical", "high", "medium"):
            picked.append(r)
        elif KEEP_LOW.search(r["id"] + " " + r["path"] + " " + r["name"]):
            picked.append(r)
        if len(picked) >= MAX_RULES * 2:
            break

    print(f"selected {len(picked)} candidate rules for validation")

    # ── validation against decoys ──
    clean, rejected = [], []
    for r in picked:
        bad = [n for n, resp in DECOYS.items() if engine._eval_rule(resp, r)]
        if bad:
            rejected.append((r, bad))
        else:
            clean.append(r)

    print(f"  passed decoys : {len(clean)}")
    print(f"  REJECTED (FP) : {len(rejected)}")
    for r, bad in rejected[:12]:
        print(f"     ✗ {r['id'][:40]:<40} fires on {bad}")

    clean = clean[:MAX_RULES]
    by = {}
    for r in clean:
        by[r["severity"]] = by.get(r["severity"], 0) + 1
    print(f"\nkeeping {len(clean)} rules:", dict(sorted(by.items(), key=lambda kv: SEV_RANK[kv[0]])))

    json.dump(clean, open("/tmp/validated_rules.json", "w"), indent=1)
    print("wrote /tmp/validated_rules.json")


if __name__ == "__main__":
    main()
