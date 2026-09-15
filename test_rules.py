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
}

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
}


def main():
    rules = {r["id"]: r for r in engine.VULN_RULES}
    print(f"Validating {len(rules)} rules × ({len(NEGATIVE)} negative + 1 positive) fixtures\n")

    missing_pos = [rid for rid in rules if rid not in POSITIVE]
    if missing_pos:
        print("NO POSITIVE FIXTURE:", missing_pos)

    fails = []
    for rid, rule in rules.items():
        # positive
        pos = POSITIVE.get(rid)
        if pos is not None and not engine._eval_rule(pos, rule):
            fails.append((rid, "POSITIVE did not fire"))
        # negatives
        for nname, nresp in NEGATIVE.items():
            if engine._eval_rule(nresp, rule):
                fails.append((rid, f"FALSE POSITIVE on '{nname}'"))

    width = max(len(r) for r in rules)
    for rid, rule in rules.items():
        bad = [f for f in fails if f[0] == rid]
        status = "\033[92mPASS\033[0m" if not bad else "\033[91mFAIL\033[0m"
        print(f"  {status}  {rid:<{width}}  [{rule['severity']:<8}] {rule['name']}")
        for _, why in bad:
            print(f"          └─ {why}")

    print()
    if fails:
        print(f"\033[91m{len(fails)} problem(s) across {len(set(f[0] for f in fails))} rule(s)\033[0m")
        return 1
    print(f"\033[92mALL {len(rules)} RULES PASS — every rule fires on its vulnerable "
          f"fixture and on none of the {len(NEGATIVE)} decoys\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
