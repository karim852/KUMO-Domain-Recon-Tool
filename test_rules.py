"""
Per-rule validation harness for Kumo's nuclei-style vulnerability playbook.

For every rule we assert:
  1. POSITIVE  — a realistic vulnerable response makes the rule fire.
  2. NEGATIVE  — none of these make it fire:
       • a soft-404 (HTTP 200 whose body says "not found")
       • a generic WAF 403 page
       • an ordinary marketing homepage
       • an empty 200
       • an HTML error page served in place of a raw file
Every rule must pass all of them.
"""
import engine


class R:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self.content = body.encode() if isinstance(body, str) else body
        self.text = body if isinstance(body, str) else body.decode("utf-8", "ignore")
        self.headers = headers or {}


JSON = {"Content-Type": "application/json"}
HTML = {"Content-Type": "text/html; charset=utf-8"}
OCTET = {"Content-Type": "application/octet-stream"}
TEXT = {"Content-Type": "text/plain"}

# ── realistic vulnerable responses, one per rule id ──
POSITIVE = {
    "git-config": R(200, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                         "[remote \"origin\"]\n\turl = git@github.com:corp/app.git\n", TEXT),
    "git-head": R(200, "ref: refs/heads/main\n", TEXT),
    "env-file": R(200, "APP_ENV=production\nAPP_KEY=base64:x9Kd==\nDB_PASSWORD=s3cr3t\nDB_HOST=127.0.0.1\n", TEXT),
    "ds-store": R(200, "Bud1\x00\x00\x00\x08docs\x00\x00", OCTET),
    "phpinfo": R(200, "<html><title>phpinfo()</title><body><h1>phpinfo()</h1>"
                      "PHP Version 8.1.2 <tr><td>Configuration File (php.ini) Path</td></tr></body></html>", HTML),
    "laravel-debug": R(200, '{"can_execute_commands":true,"config":{"editor":"vscode"}}', JSON),
    "wp-config-bak": R(200, "<?php\ndefine('DB_NAME','wp');\ndefine('DB_PASSWORD','hunter2');\n", TEXT),
    "spring-actuator-env": R(200, '{"activeProfiles":["prod"],"propertySources":'
                                  '[{"name":"systemEnvironment","properties":{}}]}', JSON),
    "spring-heapdump": R(200, "\x00" * 150000, OCTET),
    "swagger-spec": R(200, '{"swagger":"2.0","info":{"title":"API"},"paths":{"/users":{}}}', JSON),
    "jenkins-panel": R(200, "<html><title>Dashboard [Jenkins]</title></html>",
                       {"X-Jenkins": "2.426.1", "Content-Type": "text/html"}),
    "kibana-panel": R(200, '<html><body kibana-body="true">app</body></html>',
                      {"kbn-name": "kibana", "Content-Type": "text/html"}),
    "elasticsearch": R(200, '{"cluster_name":"es-prod","status":"green","number_of_nodes":3,'
                            '"active_shards":10}', JSON),
    "prometheus-metrics": R(200, "# HELP go_gc_duration_seconds A summary\n"
                                 "# TYPE go_gc_duration_seconds summary\ngo_gc_duration_seconds 0.1\n", TEXT),
    "phpmyadmin": R(200, "<html><head><title>phpMyAdmin</title></head>"
                         "<body><form><input name='pma_username'></form></body></html>", HTML),
    "adminer": R(200, "<html><body><h1>Adminer</h1><a href='https://adminer.org'>x</a>"
                      "<form>login server</form></body></html>", HTML),
    "docker-api": R(200, '{"Version":"24.0.7","ApiVersion":"1.43","GitCommit":"afdd53b",'
                         '"GoVersion":"go1.20.10"}', JSON),
    "kubernetes-api": R(200, '{"kind":"NamespaceList","apiVersion":"v1","items":[]}', JSON),
    "traefik-dashboard": R(200, "<html><title>Traefik</title><div id='traefik-app'></div></html>", HTML),
    "grafana-panel": R(200, "<html><body class='grafana-app'><script>window.grafanaBootData={};"
                            "</script><div class='loginForm'>Grafana</div></body></html>", HTML),
    "rabbitmq-mgmt": R(200, '{"management_version":"3.12.0","rabbit_version":"3.12.0"}', JSON),
    "sql-dump": R(200, "-- MySQL dump 10.13\nCREATE TABLE `users` (id int);\n"
                       "INSERT INTO `users` VALUES (1,'admin');\n", TEXT),
    "htpasswd": R(200, "admin:$apr1$xyz$abcdefghij\nops:$2y$10$abcdefghijklmno\n", TEXT),
    "npm-token": R(200, "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\n", TEXT),
    "aws-credentials": R(200, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                              "aws_secret_access_key = wJalrXUtnFEMI\n", TEXT),
    "ssh-private-key": R(200, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
                              "-----END RSA PRIVATE KEY-----\n", TEXT),
    "docker-compose": R(200, "version: '3'\nservices:\n  web:\n    image: nginx:latest\n"
                             "    environment:\n      - DB_PASS=secret\n", TEXT),
    "graphql-introspection": R(200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}', JSON),
    "sonarqube": R(200, '{"id":"AXb","version":"9.9.1","status":"UP"}', JSON),
    "wp-user-enum": R(200, '[{"id":1,"name":"admin","slug":"admin"},{"id":2,"slug":"editor"}]', JSON),
    "php2shell-unpatched-php": R(200, "<html><head><title>Site</title></head><body>hi</body></html>",
                                 {"X-Powered-By": "PHP/8.4.26", "Content-Type": "text/html"}),
}

# Version-boundary rules need their own table: a decoy cannot express "the
# patched release must not match". Each entry is (rule id, headers, expected).
VERSION_CASES = [
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.4.26"}, True,  "below 8.4.27 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.4.27"}, False, "IS the 8.4 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.4.28"}, False, "newer than fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.2.34"}, True,  "below 8.2.35 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.2.35"}, False, "IS the 8.2 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.3.35"}, True,  "below 8.3.36 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.3.36"}, False, "IS the 8.3 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.5.11"}, True,  "below 8.5.12 fix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.5.12"}, False, "IS the 8.5 fix"),
    # end-of-life branches: affected, and no upstream release will ever fix them
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.1.33"}, True,  "8.1 EOL"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.1.0"},  True,  "8.1.0 EOL"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.0.30"}, True,  "8.0 EOL"),
    # PHP 7.x — every branch, oldest to newest
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.4.33"}, True,  "7.4 (backport issued)"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.3.33"}, True,  "7.3 (distro patched)"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.2.24"}, True,  "7.2 (distro patched)"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.1.33"}, True,  "7.1"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.0.33"}, True,  "7.0"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.0.0"},  True,  "7.0.0"),
    # PHP 5.x — including below the 5.4 bound some write-ups quote
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.6.40"}, True,  "5.6"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.5.38"}, True,  "5.5"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.4.45"}, True,  "5.4"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.4.0"},  True,  "5.4.0"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.3.29"}, True,  "5.3 (NVD has no lower bound)"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.2.17"}, True,  "5.2"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/5.0.0"},  True,  "5.0.0 lower bound"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/4.4.9"},  False, "PHP 4 predates the code"),
    # parsing and evidence discipline
    ("php2shell-unpatched-php", {"Server": "Apache/2.4.41 (Ubuntu) PHP/8.3.10"}, True, "via Server header"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/8.3.7-1ubuntu2"}, True, "distro suffix"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP/7.4"},    True,  "two-component version"),
    ("php2shell-unpatched-php", {"X-Powered-By": "PHP"}, False, "no version -> no guess"),
    ("php2shell-unpatched-php", {"X-Powered-By": "ASP.NET"}, False, "not PHP"),
    ("php2shell-unpatched-php", {"Server": "nginx"}, False, "nothing advertised"),

    # ── end-of-life rule: fires only on unsupported branches ──
    ("php-eol-runtime", {"X-Powered-By": "PHP/5.6.40"}, True,  "5.6 is EOL"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/7.4.33"}, True,  "7.4 is EOL"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.0.30"}, True,  "8.0 is EOL"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.1.33"}, True,  "8.1 is EOL"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.2.34"}, False, "8.2 supported, just unpatched"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.2.35"}, False, "8.2 supported and patched"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.4.27"}, False, "8.4 supported"),
    ("php-eol-runtime", {"X-Powered-By": "PHP/8.5.12"}, False, "8.5 supported"),
    ("php-eol-runtime", {"X-Powered-By": "PHP"},        False, "no version -> no guess"),
    ("php-eol-runtime", {"Server": "nginx"},            False, "nothing advertised"),
]

# ── responses that must NEVER trigger any rule ──
NEGATIVE = {
    "soft-404": R(200, "<!doctype html><html><head><title>404 - Page Not Found</title></head>"
                       "<body><h1>Page Not Found</h1><p>Sorry, that page does not exist.</p>"
                       + "x" * 900 + "</body></html>", HTML),
    "waf-403": R(403, "<!doctype html><html><head><title>403 Forbidden</title></head>"
                      "<body><h1>Access Denied</h1>Request blocked by WAF"
                      + "y" * 1100 + "</body></html>", HTML),
    "homepage": R(200, "<!doctype html><html><head><title>ShopMax — Online Store</title></head>"
                       "<body><h1>Welcome</h1><div class='products'>Buy admin login config "
                       "services image services: users data</div>" + "z" * 2000 + "</body></html>", HTML),
    "empty-200": R(200, "", HTML),
    "html-instead-of-file": R(200, "<!doctype html><html><body>Our site uses cookies. "
                                   "Contact admin for DB_PASSWORD reset or aws_access_key_id help."
                                   "</body></html>", HTML),
    "redirect": R(302, "", {"Location": "https://example.com/login"}),
    "json-error": R(200, '{"error":"not found","status":404}', JSON),
    # Shapes that the live fplab.py hosts serve. A rule that fires on any of
    # these fires on a large slice of the ordinary web.
    "generic-json-api": R(200, '{"status":"ok","title":"Resource","message":"No handler matched",'
                               '"comment":"","pageId":0,"version":"2.4.0","data":[],'
                               '"_links":{"self":{"href":"/x"}},"timestamp":"2026-10-25T00:00:00Z"}', JSON),
    "spa-shell": R(200, "<!DOCTYPE html><html><head><title>Northwind Analytics</title>"
                        "<script type='module' src='/assets/index.js'></script></head>"
                        "<body><div id='root'></div></body></html>", HTML),
    "echo-search": R(200, "<!DOCTYPE html><html><head><title>admin login · BrandMart</title></head>"
                          "<body><h1>Search results for \"admin login\"</h1>"
                          "<p>Showing products matching admin login in our catalog.</p>"
                          + "<p class='c'>product </p>" * 80 + "</body></html>", HTML),
    "marketing-site": R(200, "<!DOCTYPE html><html><head><title>Acme Cloud — Platform</title></head>"
                             "<body><h1>Build faster</h1><p>Our API, status page, metrics dashboard, "
                             "admin console and user management help teams ship. Read the docs, see "
                             "pricing, contact sales. version 3</p><footer>© Acme</footer></body></html>", HTML),
}


def main():
    rules = {r["id"]: r for r in engine.VULN_RULES}
    print(f"Validating {len(rules)} rules × ({len(NEGATIVE)} negative + 1 positive) fixtures\n")

    missing_pos = [rid for rid in rules if rid not in POSITIVE]
    if missing_pos:
        print("NO POSITIVE FIXTURE:", missing_pos)

    fails = []
    for rid, rule in rules.items():
        # Evaluate exactly as the live scanner does, scrub included. Testing
        # without the scrub hid fourteen rules whose own evidence words were
        # being stripped before matching, so they could never fire in a scan.
        scrub = engine._rule_scrub(rule, "example.com")
        pos = POSITIVE.get(rid)
        if pos is not None and not engine._eval_rule(pos, rule, scrub):
            fails.append((rid, "POSITIVE did not fire"))
        for nname, nresp in NEGATIVE.items():
            if engine._eval_rule(nresp, rule, scrub):
                fails.append((rid, f"FALSE POSITIVE on '{nname}'"))

    width = max(len(r) for r in rules)
    for rid, rule in rules.items():
        bad = [f for f in fails if f[0] == rid]
        status = "\033[92mPASS\033[0m" if not bad else "\033[91mFAIL\033[0m"
        print(f"  {status}  {rid:<{width}}  [{rule['severity']:<8}] {rule['name']}")
        for _, why in bad:
            print(f"          └─ {why}")

    # ── the ported playbook ──────────────────────────────────────────
    # The ~335 rules mined from nuclei-templates have no hand-written positive
    # fixture, but they must still survive every decoy. This half of the harness
    # is what caught the condition-flattening bug in the porting pipeline.
    ext = engine.VULN_RULES_EXTENDED
    ext_fails = []
    for rule in ext:
        scrub = engine._rule_scrub(rule, "example.com")
        for nname, nresp in NEGATIVE.items():
            try:
                if engine._eval_rule(nresp, rule, scrub):
                    ext_fails.append((rule["id"], rule["severity"], rule["name"][:46], nname))
            except Exception as e:
                ext_fails.append((rule["id"], rule["severity"], f"CRASH: {e}"[:46], nname))

    # ── version-boundary checks ──────────────────────────────────────
    # The case that matters most is the negative one: a host running the FIXED
    # release must produce nothing. A version rule that fires on a patched host
    # is worse than no rule, because it trains the operator to ignore it.
    allr = {r["id"]: r for r in engine.VULN_RULES + ext}
    ver_fails = []
    for rid, hdrs, want, why in VERSION_CASES:
        rule = allr.get(rid)
        if rule is None:
            ver_fails.append((rid, "rule missing", why))
            continue
        got = engine._eval_rule(R(200, "<html><body>x</body></html>", hdrs), rule,
                                engine._rule_scrub(rule, "example.com"))
        if got is not want:
            ver_fails.append((rid, f"expected {want}, got {got}", why))
    print(f"\n  Version boundaries: {len(VERSION_CASES)} cases")
    for rid, what, why in ver_fails:
        print(f"    \033[91mFAIL\033[0m {rid:<30} {what}  ({why})")
    if not ver_fails:
        print("    \033[92mevery boundary correct, patched releases silent\033[0m")

    # ── dead-rule check ──────────────────────────────────────────────
    # A rule whose evidence never survives its own scrub can never fire. These
    # are invisible in a scan: no error, no finding, just silence.
    dead = []
    for rule in engine.VULN_RULES + ext:
        scrub = {s.lower() for s in engine._rule_scrub(rule, "example.com")}
        for m in rule.get("matchers", []):
            if m.get("type") != "word":
                continue
            ws = [str(w).lower() for w in (m.get("words") or [])]
            if not ws:
                continue
            killed = [w for w in ws if any(s in w or w in s for s in scrub)]
            if (m.get("condition") == "and" and killed) or \
               (m.get("condition") != "and" and len(killed) == len(ws)):
                dead.append((rule["id"], rule["path"]))
                break
    print(f"\n  Dead-rule check: {len(engine.VULN_RULES) + len(ext)} rules")
    for rid, p in dead[:20]:
        print(f"    \033[91mDEAD\033[0m {rid:<40} evidence scrubbed by its own path {p}")
    if not dead:
        print("    \033[92mevery rule's evidence survives its own path scrub\033[0m")
    ext_fails += [(rid, "dead", "evidence scrubbed by own path", p) for rid, p in dead]

    print(f"\n  Ported playbook: {len(ext)} rules × {len(NEGATIVE)} decoys")
    for rid, sev, name, nname in ext_fails[:30]:
        print(f"    \033[91mFALSE POSITIVE\033[0m [{sev:<8}] {rid:<40} fires on '{nname}'  {name}")
    if len(ext_fails) > 30:
        print(f"    … and {len(ext_fails)-30} more")
    if not ext_fails:
        print("    \033[92mno ported rule fires on any decoy\033[0m")

    ext_fails += [(rid, "version", what, why) for rid, what, why in ver_fails]

    print()
    if fails or ext_fails:
        if fails:
            print(f"\033[91m{len(fails)} problem(s) across "
                  f"{len(set(f[0] for f in fails))} hand-written rule(s)\033[0m")
        if ext_fails:
            print(f"\033[91m{len(ext_fails)} false positive(s) across "
                  f"{len(set(f[0] for f in ext_fails))} ported rule(s)\033[0m")
        return 1
    print(f"\033[92mALL {len(rules)} hand-written rules fire on their vulnerable fixture, "
          f"and none of the {len(rules) + len(ext)} rules fire on any of the "
          f"{len(NEGATIVE)} decoys\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
