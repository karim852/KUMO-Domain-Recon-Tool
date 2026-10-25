"""
Kumo false-positive lab — the negative-control counterpart to lab.py.

lab.py plants real exposures and asks "does Kumo find them?" (false negatives).
This lab plants NOTHING and asks the harder question: "does Kumo invent
findings on a host where there is nothing to find?" (false positives).

Every profile below is a real-world shape that makes naive scanners hallucinate.
All of them serve a target with ZERO genuine exposures, so for the exposure
modules the correct answer on every one of them is: no findings.

Profiles are selected by the Host header, so one pair of listeners (80/443)
serves them all. Add the names to /etc/hosts pointing at 127.0.0.1:

    127.0.0.1  spa.fptest soft404.fptest waf.fptest echo.fptest
    127.0.0.1  jsonapi.fptest clean.fptest redirect.fptest

  spa.fptest       every path returns the same 200 SPA shell (React/Vue router)
  soft404.fptest   every unknown path returns 200 with a friendly "not found"
  waf.fptest       every path returns 403 from a WAF, with a per-request id
  echo.fptest      CMS search page: 200, title echoes the requested path
  jsonapi.fptest   API gateway: 200 JSON with generic keys on every path
  clean.fptest     a correctly built, hardened site with honest 404s
  redirect.fptest  every unknown path 302-redirects to the homepage
  phpfixed.fptest  PHP that IS patched (8.4.27) — a version rule must not fire
  phphidden.fptest PHP with the version suppressed — nothing to conclude

Padding lengths are derived from a hash of the path, so a given path always
answers with the same size (deterministic runs) while different paths differ —
which is exactly what defeats size-only catch-all detection in the real world.
"""
import hashlib
import http.server
import json
import os
import socketserver
import ssl
import subprocess
import threading
import time

HOST = "0.0.0.0"

VHOSTS = ["spa.fptest", "soft404.fptest", "waf.fptest", "echo.fptest",
          "jsonapi.fptest", "clean.fptest", "redirect.fptest",
          "phpfixed.fptest", "phphidden.fptest"]


def _jitter(path, lo, hi):
    """Deterministic per-path filler length in [lo, hi]."""
    h = int(hashlib.md5(path.encode()).hexdigest()[:8], 16)
    return lo + (h % max(1, hi - lo + 1))


def _filler(path, lo, hi, word="content"):
    n = _jitter(path, lo, hi)
    unit = f"<p class='c'>{word} </p>"
    return unit * max(0, n // len(unit))


# ─────────────────────────────────────────────────────────────────
# PROFILE: SPA catch-all — identical shell for every route
# ─────────────────────────────────────────────────────────────────
SPA_SHELL = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northwind Analytics</title>
<link rel="stylesheet" href="/assets/index-4f2a1b.css">
<script type="module" crossorigin src="/assets/index-9c3e7d.js"></script>
</head><body>
<div id="root"></div>
<noscript>You need JavaScript to run this app.</noscript>
</body></html>"""


def profile_spa(path, qs):
    if path == "/assets/index-9c3e7d.js":
        return 200, "application/javascript", "const e={api:'/api'};export default e;"
    if path == "/robots.txt":
        return 200, "text/plain", "User-agent: *\nAllow: /\n"
    # client-side router: the server has no idea what the path means
    return 200, "text/html", SPA_SHELL


# ─────────────────────────────────────────────────────────────────
# PROFILE: soft-404 — HTTP 200 for a page that says "not found"
# ─────────────────────────────────────────────────────────────────
SOFT404_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ShopCo — Home</title></head><body>
<h1>ShopCo</h1><p>Everything for your home.</p>
<a href="/catalog">Catalog</a> <a href="/contact">Contact</a>
</body></html>"""


def profile_soft404(path, qs):
    if path in ("/", "/index.html"):
        return 200, "text/html", SOFT404_HOME
    if path == "/robots.txt":
        return 200, "text/plain", "User-agent: *\nDisallow: /cart\n"
    if path == "/catalog":
        return 200, "text/html", "<html><head><title>Catalog — ShopCo</title></head><body>items</body></html>"
    # The classic: 200 OK on a page whose own text says it does not exist,
    # with modest size variance from the echoed path and suggestion list.
    body = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>Page not found — ShopCo</title></head><body>"
            f"<h1>We couldn't find that page</h1>"
            f"<p>Sorry, <code>{path}</code> does not exist. Try our catalog.</p>"
            f"{_filler(path, 0, 400, 'suggestion')}"
            f"</body></html>")
    return 200, "text/html", body


# ─────────────────────────────────────────────────────────────────
# PROFILE: WAF — 403 on everything, with a per-request trace id
# ─────────────────────────────────────────────────────────────────
def profile_waf(path, qs):
    ref = hashlib.md5((path + qs).encode()).hexdigest()[:18].upper()
    body = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>Access Denied</title></head><body>"
            f"<h1>Access Denied</h1>"
            f"<p>Your request has been blocked by our security policy.</p>"
            f"<p>Reference ID: {ref}</p>"
            f"<p>Support ID: {int(ref[:8], 16)}</p>"
            f"{_filler(path, 0, 300, 'notice')}"
            f"</body></html>")
    return 403, "text/html", body


# ─────────────────────────────────────────────────────────────────
# PROFILE: path echo — CMS search page titled with the requested path
# ─────────────────────────────────────────────────────────────────
def profile_echo(path, qs):
    if path == "/":
        return 200, "text/html", ("<!DOCTYPE html><html><head><title>BrandMart — Online Store</title>"
                                  "</head><body><h1>BrandMart</h1><p>Shop everything.</p></body></html>")
    term = path.strip("/").replace("/", " ").replace(".", " ")
    # A real search/catalog handler: 200, reflects the term in <title> and body,
    # and the result count makes page size vary a lot between paths.
    body = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{term} · BrandMart</title></head><body>"
            f"<h1>Search results for \"{term}\"</h1>"
            f"<p>Showing products matching {term} in our catalog.</p>"
            f"{_filler(path, 200, 5000, 'product')}"
            f"</body></html>")
    return 200, "text/html", body


# ─────────────────────────────────────────────────────────────────
# PROFILE: JSON API gateway — 200 JSON with very generic keys
# ─────────────────────────────────────────────────────────────────
def profile_jsonapi(path, qs):
    payload = {
        "status": "ok",
        "title": "Resource",
        "message": "No handler matched this route",
        "comment": "",
        "pageId": 0,
        "version": "2.4.0",
        "data": [],
        "_links": {"self": {"href": path}},
        "timestamp": "2026-10-25T00:00:00Z",
    }
    return 200, "application/json", json.dumps(payload)


# ─────────────────────────────────────────────────────────────────
# PROFILE: clean — a properly built site, honest 404s, full headers
# ─────────────────────────────────────────────────────────────────
CLEAN_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Meridian Consulting</title></head><body>
<h1>Meridian Consulting</h1>
<p>Independent advisory for regulated industries.</p>
</body></html>"""

CLEAN_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def profile_clean(path, qs):
    if path in ("/", "/index.html"):
        return 200, "text/html", CLEAN_HOME
    if path == "/robots.txt":
        return 200, "text/plain", "User-agent: *\nAllow: /\n"
    return 404, "text/html", "<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>404</h1></body></html>"


# ─────────────────────────────────────────────────────────────────
# PROFILE: redirect-everything
# ─────────────────────────────────────────────────────────────────
def profile_redirect(path, qs):
    if path == "/":
        return 200, "text/html", "<!DOCTYPE html><html><head><title>Portal</title></head><body>Welcome</body></html>"
    return 302, "text/html", ""


# ─────────────────────────────────────────────────────────────────
# PROFILE: PHP that is already patched, and PHP with the version hidden
# ─────────────────────────────────────────────────────────────────
# Negative controls for version-boundary rules. A rule that reports an
# unpatched runtime must stay silent on a host running the FIXED release, and
# must not infer a version it was never told — "PHP is present" is not a
# version. These two hosts are how that stays true.
PHP_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Riverside Dental</title></head><body>
<h1>Riverside Dental</h1><p>Book an appointment.</p>
</body></html>"""


def profile_phpfixed(path, qs):
    if path in ("/", "/index.php", "/index.html"):
        return 200, "text/html", PHP_HOME
    return 404, "text/html", "<html><head><title>Not Found</title></head><body><h1>404</h1></body></html>"


profile_phphidden = profile_phpfixed

# Headers per host: the patched host advertises the fixed release, the hidden
# host advertises PHP without any version at all.
EXTRA_HEADERS = {
    "phpfixed.fptest":  {"X-Powered-By": "PHP/8.4.27",
                         "Server": "Apache/2.4.62 (Debian)"},
    "phphidden.fptest": {"X-Powered-By": "PHP", "Server": "Apache"},
}

PROFILES = {
    "spa.fptest":      profile_spa,
    "soft404.fptest":  profile_soft404,
    "waf.fptest":      profile_waf,
    "echo.fptest":     profile_echo,
    "jsonapi.fptest":  profile_jsonapi,
    "clean.fptest":    profile_clean,
    "redirect.fptest": profile_redirect,
    "phpfixed.fptest":  profile_phpfixed,
    "phphidden.fptest": profile_phphidden,
}

# Ground truth: none of these hosts has a single genuine exposure.
EXPECTED_FINDINGS = {h: 0 for h in PROFILES}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _profile(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host, PROFILES.get(host)

    def _respond(self, head=False):
        path = self.path.split("?")[0]
        qs = self.path[len(path):]
        host, fn = self._profile()
        if fn is None:
            self.send_response(421)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        code, ctype, body = fn(path, qs)
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if host == "clean.fptest":
            for k, v in CLEAN_HEADERS.items():
                self.send_header(k, v)
        for k, v in EXTRA_HEADERS.get(host, {}).items():
            self.send_header(k, v)
        if code == 302:
            self.send_header("Location", "/")
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except Exception:
                pass

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(head=True)

    def do_POST(self):
        self._respond()

    def do_OPTIONS(self):
        self._respond()


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_cert():
    key, crt = "/tmp/fplab.key", "/tmp/fplab.crt"
    if not os.path.exists(crt):
        san = ",".join(f"DNS:{h}" for h in VHOSTS) + ",IP:127.0.0.1"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", crt, "-days", "365", "-nodes",
             "-subj", "/C=US/ST=Test/L=Test/O=Kumo FP Lab/CN=fptest",
             "-addext", f"subjectAltName={san}"],
            check=True, capture_output=True)
    return key, crt


def ensure_hosts():
    """Make the vhost names resolve to localhost."""
    try:
        with open("/etc/hosts", "r") as f:
            current = f.read()
        missing = [h for h in VHOSTS if h not in current]
        if missing:
            with open("/etc/hosts", "a") as f:
                f.write("\n# kumo fp lab\n127.0.0.1 " + " ".join(missing) + "\n")
    except Exception as e:
        print("could not update /etc/hosts:", e)


def start():
    ensure_hosts()
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
    time.sleep(0.8)


if __name__ == "__main__":
    start()
    print("Kumo FP lab running on 80/443 for: " + ", ".join(VHOSTS))
    while True:
        time.sleep(3600)
