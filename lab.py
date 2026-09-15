"""
Kumo test lab — a deliberately vulnerable target running on localhost.

Replicates the kinds of exposures found on the public, sanctioned practice
targets (testphp.vulnweb.com, demo.testfire.net, badssl.com, scanme.nmap.org)
so every Kumo module can be exercised end-to-end over a real network stack:
real sockets, real HTTP, real TLS, real banners.

Ports
  80    vulnerable web app (git/env/phpinfo/phpMyAdmin/WP/Swagger/Actuator/...)
  443   same app over TLS with a self-signed certificate
  9200  Elasticsearch-like API
  22    SSH banner
  3306  MySQL banner
  21    FTP banner
"""
import http.server
import json
import os
import socket
import socketserver
import ssl
import subprocess
import threading
import time

HOST = "127.0.0.1"

JS_BUNDLE = """
// main bundle
var chunks={0:"/static/js/453.chunk.js"};
const CONFIG={
  apiBase:"/api/v1",
  stripeKey:"sk_live_51H8xKpLmQwRtYuIoPaSdFgHjKlZx",
  googleMaps:"AIzaSyD9x7Kp2Lm4Qw8Rt6Yu1Io3Pa5Sd7Fg9Hj",
  docsPlaceholder:"YOUR_API_KEY_HERE"
};
fetch("/api/v1/users");fetch("/api/v1/admin/config");fetch("/wp-json/wp/v2/posts");
// TODO: remove hardcoded admin password before launch
"""

CHUNK_JS = """
export const S={
  db:"mongodb+srv://svcuser:Pa55w0rd@cluster0.abcde.mongodb.net/prod",
  github:"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
  aws:"AKIAIOSFODNN7EXAMPLE",
  bucket:"corp-backups.s3.amazonaws.com",
  internal:"https://api-internal.corp.local:8443/v2/billing"
};
"""

HOMEPAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Acme Test Corp — Secure Banking Demo</title>
<link rel="icon" href="/favicon.ico">
<script src="/static/js/main.js"></script>
<link rel="modulepreload" href="/static/js/runtime.js">
</head><body>
<h1>Acme Test Corp</h1>
<p>Contact <a href="mailto:admin@acme-test.local">admin@acme-test.local</a>
or support@acme-test.local. Internal host: db01.corp.local (10.0.0.14)</p>
<script>window.__ENV__={apiKey:"AIzaSyD9x7Kp2Lm4Qw8Rt6Yu1Io3Pa5Sd7Fg9Hj",debug:true};</script>
<a href="/login.php">Login</a> <a href="/admin/">Admin</a>
</body></html>"""

ROUTES = {
    "/": (200, "text/html", HOMEPAGE),
    "/index.html": (200, "text/html", HOMEPAGE),
    "/static/js/main.js": (200, "application/javascript", JS_BUNDLE),
    "/static/js/453.chunk.js": (200, "application/javascript", CHUNK_JS),
    "/static/js/runtime.js": (200, "application/javascript",
                              'var t="glpat-A1b2C3d4E5f6G7h8I9j0";'),

    # ── exposed files (rule playbook targets) ──
    "/.git/config": (200, "text/plain",
                     "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                     "[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n"),
    "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
    "/.env": (200, "text/plain",
              "APP_ENV=production\nAPP_KEY=base64:Zm9vYmFyYmF6\n"
              "DB_HOST=127.0.0.1\nDB_PASSWORD=sup3rs3cret\nMAIL_HOST=smtp.acme.local\n"),
    "/.htpasswd": (200, "text/plain", "admin:$apr1$q8Nf2s$JkL9mN0pQrStUvWxYz\n"),
    "/.npmrc": (200, "text/plain", "//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n"),
    "/.aws/credentials": (200, "text/plain",
                          "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                          "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n"),
    "/id_rsa": (200, "text/plain",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAy8Dbv8\n-----END RSA PRIVATE KEY-----\n"),
    "/dump.sql": (200, "text/plain",
                  "-- MySQL dump 10.13  Distrib 8.0.35\n"
                  "CREATE TABLE `users` (`id` int, `email` varchar(64));\n"
                  "INSERT INTO `users` VALUES (1,'admin@acme-test.local');\n"),
    "/docker-compose.yml": (200, "text/plain",
                            "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n"
                            "    environment:\n      - DB_PASS=sup3rs3cret\n"),
    "/wp-config.php.bak": (200, "text/plain",
                           "<?php\ndefine('DB_NAME','wordpress');\n"
                           "define('DB_PASSWORD','hunter2');\ndefine('AUTH_KEY','x');\n"),
    "/.DS_Store": (200, "application/octet-stream", "Bud1\x00\x00\x00\x08admin\x00backup\x00"),

    # ── panels / apps ──
    "/phpinfo.php": (200, "text/html",
                     "<html><head><title>phpinfo()</title></head><body><h1>phpinfo()</h1>"
                     "<tr><td>PHP Version</td><td>8.1.2</td></tr>"
                     "<tr><td>Configuration File (php.ini) Path</td><td>/etc/php</td></tr>"
                     "</body></html>"),
    "/phpmyadmin/": (200, "text/html",
                     "<html><head><title>phpMyAdmin</title></head><body>"
                     "<form action='index.php'><input name='pma_username'>"
                     "<input name='pma_password' type='password'></form></body></html>"),
    "/adminer.php": (200, "text/html",
                     "<html><head><title>Login - Adminer</title></head><body>"
                     "<h1>Adminer <a href='https://www.adminer.org'>4.8.1</a></h1>"
                     "<form><input name='server'>login</form></body></html>"),
    "/login.php": (200, "text/html",
                   "<html><head><title>Login</title></head><body>"
                   "<form method=post><input name=uname><input name=pass type=password>"
                   "</form></body></html>"),
    "/admin/": (200, "text/html",
                "<html><head><title>Admin Login</title></head><body>"
                "<form>admin login password</form></body></html>"),

    # ── APIs / specs ──
    "/actuator/env": (200, "application/json",
                      json.dumps({"activeProfiles": ["prod"],
                                  "propertySources": [{"name": "systemEnvironment",
                                                       "properties": {"DB_PASSWORD": {"value": "******"}}}]})),
    "/actuator/health": (200, "application/json", '{"status":"UP"}'),
    "/actuator": (200, "application/json", '{"_links":{"self":{"href":"/actuator"}}}'),
    "/swagger.json": (200, "application/json",
                      json.dumps({"swagger": "2.0", "info": {"title": "Acme API", "version": "1.0"},
                                  "paths": {"/users": {"get": {}}, "/admin": {"get": {}}}})),
    "/v3/api-docs": (200, "application/json",
                     json.dumps({"openapi": "3.0.1", "info": {"title": "Acme"},
                                 "paths": {"/users": {}}})),
    "/wp-json": (200, "application/json",
                 '{"name":"Acme","description":"demo","routes":{},"_links":{}}'),
    "/wp-json/wp/v2/users": (200, "application/json",
                             '[{"id":1,"name":"admin","slug":"admin"},'
                             '{"id":2,"name":"editor","slug":"editor"}]'),
    "/api/v1": (200, "application/json", '{"version":"1.0","endpoints":12}'),
    "/api/v1/users": (200, "application/json",
                      '[{"id":1,"email":"admin@acme-test.local"},{"id":2,"email":"bob@acme-test.local"}]'),
    "/api/v1/admin/config": (401, "application/json", '{"error":"unauthorized"}'),
    "/api/v1/health": (200, "application/json", '{"status":"ok"}'),
    "/api": (200, "application/json", '{"api":"v1"}'),
    "/metrics": (200, "text/plain",
                 "# HELP http_requests_total Total requests\n"
                 "# TYPE http_requests_total counter\nhttp_requests_total 4242\n"),
    "/api/system/status": (200, "application/json", '{"id":"AXb","version":"9.9.1","status":"UP"}'),

    # ── misc discovery ──
    "/robots.txt": (200, "text/plain",
                    "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"
                    "Disallow: /.git/\nSitemap: http://localhost/sitemap.xml\n"),
    "/sitemap.xml": (200, "application/xml",
                     '<?xml version="1.0"?><urlset><url><loc>http://localhost/</loc></url>'
                     '<url><loc>http://localhost/login.php</loc></url></urlset>'),
    "/.well-known/security.txt": (200, "text/plain",
                                  "Contact: mailto:security@acme-test.local\nExpires: 2027-01-01T00:00:00z\n"),
    "/crossdomain.xml": (200, "application/xml",
                         '<?xml version="1.0"?><cross-domain-policy>'
                         '<allow-access-from domain="*"/></cross-domain-policy>'),
    "/favicon.ico": (200, "image/x-icon", "\x00\x00\x01\x00" + "F" * 400),
}

# ── CMS / platform exposures ported from nuclei templates (rule fixtures) ──
CMS_ROUTES = {
    '/images/json': (200, 'application/json', '{ "meta":"docker demo", "f0": ""ParentId":", "f1": ""Containers":", "f2": ""Labels":" }'),
    '/ipython/tree': (200, 'text/html', '<!DOCTYPE html><html><head><title>Jupyter</title></head><body>ipython/static/components ipython/kernelspecs</body></html>'),
    '/admin/': (200, 'text/html', '<!DOCTYPE html><html><head><title>Airflow</title></head><body><title>Airflow - DAGs</title></body></html>'),
    '/admin_dev.php': (200, 'text/html', '<!DOCTYPE html><html><head><title>Symfony</title></head><body>x-debug-token-link: /_profiler/ debug mode</a> is enabled. id="sfWebDebugSymfony"</body></html>'),
    '/app/etc/local.xml': (200, 'text/html', '<!DOCTYPE html><html><head><title>Magento</title></head><body>* Magento <dbname></body></html>'),
    '/artemis/env': (200, 'text/html', '<!DOCTYPE html><html><head><title>Spring</title></head><body>applicationConfig activeProfiles server.port local.server.port application/vnd.spring-boot.actuator application/vnd.spring-boot.actuator.v1+json</body></html>'),
    '/asf/terminal': (200, 'text/html', '<!DOCTYPE html><html><head><title>Laravel</title></head><body>Laravel Terminal terminal.endpoint</body></html>'),
    '/manage.py': (200, 'text/html', '<!DOCTYPE html><html><head><title>Django</title></head><body>SECRET_KEY =</body></html>'),
    '/nagioslogserver/install': (200, 'text/html', '<!DOCTYPE html><html><head><title>Nagios</title></head><body>Nagios Log Server Install</a></body></html>'),
    '/setup/setupcluster-start.action': (200, 'text/html', '<!DOCTYPE html><html><head><title>Confluence</title></head><body>Choose your deployment type - Confluence</body></html>'),
    '/v2/auth/roles': (200, 'application/json', '{ "meta":"etcd demo", "f0": ""roles"", "f1": ""permissions"", "f2": ""role"", "f3": ""kv"" }'),
    '/artifactory/api/build': (200, 'application/json', '{ "meta":"artifactory demo", "f0": ""builds"", "f1": ""uri"", "f2": ""lastStarted"", "f3": "application/vnd.org.jfrog" }'),
    '/kustomization.yml': (200, 'text/html', '<!DOCTYPE html><html><head><title>Kubernetes</title></head><body>apiVersion: resources: namespace: commonLabels: Kustomization</body></html>'),
    '/libraries/joomla/database/': (200, 'text/html', '<!DOCTYPE html><html><head><title>Joomla</title></head><body>Index of /libraries/joomla/database Parent Directory</body></html>'),
    '/loki/api/v1/labels': (200, 'application/json', '{ "meta":"grafana demo", "f0": ""status":"success"" }'),
    '/redis.conf': (200, 'text/html', '<!DOCTYPE html><html><head><title>Redis</title></head><body>bind protected-mode port</body></html>'),
    '/signup': (200, 'text/html', '<!DOCTYPE html><html><head><title>Jenkins</title></head><body>Create an account! [Jenkins] Register [Jenkins] Register - Jenkins</body></html>'),
    '/system/storage/logs/error.log': (200, 'text/html', '<!DOCTYPE html><html><head><title>Opencart</title></head><body>PHP Notice PHP Warning PHP Error PHP Fatal error opencart catalog/controller</body></html>'),
    '/wp-content/debug.log': (200, 'text/html', '<!DOCTYPE html><html><head><title>Wordpress</title></head><body>nextgen</body></html>'),
    '/admin/master/console/config': (200, 'application/json', '{ "meta":"keycloak demo", "f0": ""realm":", "f1": ""resource":", "f2": ""auth-server-url":" }'),
    '/examples/servlets/servlet/CookieExample': (200, 'text/html', '<!DOCTYPE html><html><head><title>Tomcat</title></head><body>Cookies Example Your browser is sending the following cookies:</body></html>'),
    '/mini-profiler-resources/results': (200, 'text/html', '<!DOCTYPE html><html><head><title>Umbraco</title></head><body>StartupProfiler var profiler = "DurationMilliseconds"</body></html>'),
    "/sitecore/'": (200, 'text/html', '<!DOCTYPE html><html><head><title>Sitecore</title></head><body>extranet\\Anonymous</body></html>'),
    '/sites/': (200, 'text/html', '<!DOCTYPE html><html><head><title>Drupal</title></head><body>Index of / Last modified Parent Directory</body></html>'),
}

ROUTES.update(CMS_ROUTES)


def graphql_body(qs):
    if "__schema" in qs or "__typename" in qs:
        return '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    return '{"errors":[{"message":"Must provide query string"}]}'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.41"
    sys_version = "(Ubuntu) PHP/8.1.2"

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # deliberately leaky / missing-security headers for the header modules
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("X-Backend-Server", "web03.corp.local")
        self.send_header("X-Debug-Token-Link", "/_profiler/a1b2c3")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        self.send_header("Set-Cookie", "tracking=xyz789; Path=/")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_OPTIONS(self):
        self._send(200, "text/plain", "", {"Allow": "GET, POST, OPTIONS, PUT, DELETE"})

    def do_POST(self):
        self.do_GET()

    def do_GET(self, head=False):
        path = self.path.split("?")[0]
        qs = self.path[len(path):]

        if path.rstrip("/") in ("/graphql", "/api/graphql"):
            self._send(200, "application/json", graphql_body(qs))
            return

        if path in ROUTES:
            code, ctype, body = ROUTES[path]
            self._send(code, ctype, body)
            return

        # honest 404 for everything else (NOT a soft-404, NOT a catch-all)
        self._send(404, "text/html",
                   "<html><head><title>404 Not Found</title></head>"
                   "<body><h1>Not Found</h1></body></html>")


class ES(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/_cluster/health"):
            b = json.dumps({"cluster_name": "acme-es", "status": "green",
                            "number_of_nodes": 3, "active_shards": 12}).encode()
        else:
            b = json.dumps({"name": "es01", "cluster_name": "acme-es",
                            "version": {"number": "7.10.2"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def banner_server(port, banner):
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, port))
        except OSError:
            return
        s.listen(16)
        while True:
            try:
                c, _ = s.accept()
                c.sendall(banner)
                time.sleep(0.15)
                c.close()
            except Exception:
                return
    threading.Thread(target=loop, daemon=True).start()


def make_cert():
    key, crt = "/tmp/lab.key", "/tmp/lab.crt"
    if not os.path.exists(crt):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", crt, "-days", "365", "-nodes",
             "-subj", "/C=US/ST=Test/L=Test/O=Acme Test Corp/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,DNS:www.localhost,IP:127.0.0.1"],
            check=True, capture_output=True)
    return key, crt


def start():
    http_srv = Threaded((HOST, 80), Handler)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()

    try:
        key, crt = make_cert()
        tls_srv = Threaded((HOST, 443), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        tls_srv.socket = ctx.wrap_socket(tls_srv.socket, server_side=True)
        threading.Thread(target=tls_srv.serve_forever, daemon=True).start()
    except Exception as e:
        print("TLS listener failed:", e)

    es = Threaded((HOST, 9200), ES)
    threading.Thread(target=es.serve_forever, daemon=True).start()

    banner_server(22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
    banner_server(21, b"220 ProFTPD 1.3.6 Server (Acme FTP) [127.0.0.1]\r\n")
    banner_server(3306, b"\x4a\x00\x00\x00\x0a8.0.35-0ubuntu0.22.04.1\x00")
    banner_server(25, b"220 mail.acme-test.local ESMTP Postfix (Ubuntu)\r\n")
    time.sleep(0.8)


if __name__ == "__main__":
    start()
    print("Kumo test lab running on 127.0.0.1 (80, 443, 9200, 22, 21, 3306, 25)")
    while True:
        time.sleep(3600)
