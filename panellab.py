"""
Control panel lab — real panel login pages on their real ports, plus the
decoys that must not match.

Binds on 127.0.0.1:

Panels run on 127.0.0.2; the decoys get their own addresses, so a decoy never
sees a panel port.

  2083   cPanel login
  2087   WHM login
  8443   Plesk Obsidian login
  2222   DirectAdmin login
  10000  Webmin login
  8090   CyberPanel login
  9090   Cockpit login
  8099   an ordinary app on a non-panel port (must never be a panel)
  2031   a service that answers but shows no panel interface

And on port 80 by Host header:

  hosting.panltest   a WEB HOSTING COMPANY's marketing site. Mentions cPanel,
                     Plesk, WHM and DirectAdmin on every line while running
                     none of them. This is the decoy that matters: a scanner
                     matching the product name in prose reports a panel on
                     every hosting provider's website.
  plain.panltest     an ordinary site

    python3 panellab.py
"""
import http.server
import socketserver
import ssl
import os
import subprocess
import threading
import time

# Panels and decoys live on DIFFERENT loopback addresses. If everything shared
# 127.0.0.1 the decoy hosts would see the panel ports too, and the test would
# prove nothing about detection.
PANEL_IP = "127.0.0.2"     # the host that really runs control panels
HOSTING_IP = "127.0.0.3"   # a hosting company's marketing site, no panels
PLAIN_IP = "127.0.0.4"     # an ordinary site, no panels

VHOSTS = [("panel.panltest", PANEL_IP),
          ("hosting.panltest", HOSTING_IP),
          ("plain.panltest", PLAIN_IP)]

# ── panel login pages, as each one actually serves them ──────────────────
CPANEL = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>cPanel Login</title>
<link rel="stylesheet" href="/cPanel_magic_revision_1700000000/unprotected/styled/basic/login.css">
</head><body class="cpanel-login">
<div id="cpanel-logo"></div>
<form action="/login/?login_only=1" method="post">
<input id="user" name="user"><input id="pass" name="pass" type="password">
</form></body></html>"""

WHM = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WHM Login</title></head><body>
<form action="/login/?login_only=1" method="post">
<input name="user"><input name="pass" type="password"></form>
<div class="whostmgr-footer">WebHost Manager</div>
</body></html>"""

PLESK = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Plesk Obsidian 18.0.58</title></head><body>
<form id="loginForm" method="post" action="/login_up.php">
<input name="login_name"><input name="passwd" type="password"></form>
<div class="plesk-footer">Plesk Obsidian 18.0.58</div>
</body></html>"""

DIRECTADMIN = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>DirectAdmin Login</title></head><body>
<h1>DirectAdmin Web Control Panel</h1>
<form method="post" action="/CMD_LOGIN">
<input name="username"><input name="password" type="password"></form>
</body></html>"""

WEBMIN = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Login to Webmin</title></head><body>
<form action="/session_login.cgi" method="post">
<input name="user"><input name="pass" type="password"></form>
<div>Webmin 2.021</div></body></html>"""

CYBERPANEL = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CyberPanel - Login</title></head><body>
<form method="post"><input name="username"><input name="password" type="password"></form>
<div>CyberPanel 2.3.4</div></body></html>"""

COCKPIT = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Cockpit</title>
<script src="/cockpit/static/login.js"></script></head><body>
<script>var is_cockpit_client = false;</script>
<div id="login"></div></body></html>"""

# an ordinary app, on a port that is not a panel port
ORDINARY_APP = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Internal Metrics</title></head><body><h1>Metrics</h1>
<p>service up</p></body></html>"""

# answers on a panel port, but is not a panel
NOT_A_PANEL = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>nginx</title></head><body><h1>Welcome to nginx!</h1></body></html>"""

PORT_PAGES = {
    2083: CPANEL,
    2087: WHM,
    8443: PLESK,
    2222: DIRECTADMIN,
    10000: WEBMIN,
    8090: CYBERPANEL,
    9090: COCKPIT,
    8099: ORDINARY_APP,
    2031: NOT_A_PANEL,
}

TLS_PORTS = {2083, 2087, 8443, 9090}

# ── the decoys on port 80 ────────────────────────────────────────────────
HOSTING_SITE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Meridian Hosting — cPanel hosting from $3/month</title></head><body>
<h1>Fast cPanel hosting</h1>
<p>Every Meridian Hosting plan includes <b>cPanel</b> and <b>WHM</b> at no
extra cost. Prefer <b>Plesk</b>? Our Windows plans ship Plesk Obsidian as
standard, and our reseller plans include WHM with full DirectAdmin migration
support.</p>
<h2>Why cPanel?</h2>
<p>cPanel Login is simple, Webmin is available on VPS plans, and our
DirectAdmin Login option suits resellers. We migrate from Plesk Onyx, Plesk
Obsidian, CyberPanel and aaPanel free of charge.</p>
<ul>
<li>cPanel Login on every shared plan</li>
<li>WHM Login for resellers</li>
<li>Webmin and Virtualmin on VPS</li>
<li>Login to Webmin from your dashboard</li>
</ul>
<a href="/plans">See cPanel plans</a>
</body></html>"""

PLAIN_SITE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Castellan Architects</title></head><body>
<h1>Castellan Architects</h1><p>Studio practice, est. 1998.</p></body></html>"""

VHOST_PAGES = {
    "hosting.panltest": HOSTING_SITE,
    "plain.panltest": PLAIN_SITE,
}

EXPECTED_PANELS = {
    2083: "cPanel", 2087: "WHM", 8443: "Plesk", 2222: "DirectAdmin",
    10000: "Webmin", 8090: "CyberPanel", 9090: "Cockpit",
}


def _handler_for(port):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "nginx"
        sys_version = ""

        def log_message(self, *a):
            pass

        def _send(self, head=False):
            if port == 80:
                host = (self.headers.get("Host") or "").split(":")[0].lower()
                body = VHOST_PAGES.get(host)
                if body is None:
                    self.send_response(421)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            else:
                body = PORT_PAGES.get(port, NOT_A_PANEL)
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            if port == 2083:
                self.send_header("Set-Cookie", "cprelogin=no; path=/")
            if port == 8443:
                self.send_header("Set-Cookie", "PLESKSESSID=abc123; path=/")
            self.end_headers()
            if not head:
                try:
                    self.wfile.write(raw)
                except Exception:
                    pass

        def do_GET(self):
            self._send()

        def do_HEAD(self):
            self._send(head=True)
    return H


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_cert():
    key, crt = "/tmp/panellab.key", "/tmp/panellab.crt"
    if not os.path.exists(crt):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", crt, "-days", "365", "-nodes",
             "-subj", "/C=US/ST=Test/L=Test/O=Kumo Panel Lab/CN=panltest",
             "-addext", "subjectAltName=DNS:hosting.panltest,DNS:plain.panltest,IP:127.0.0.1"],
            check=True, capture_output=True)
    return key, crt


def ensure_hosts():
    try:
        current = open("/etc/hosts").read()
        missing = [(h, ip) for h, ip in VHOSTS if h not in current]
        if missing:
            with open("/etc/hosts", "a") as f:
                f.write("\n# kumo panel lab\n")
                for h, ip in missing:
                    f.write(f"{ip} {h}\n")
    except Exception as e:
        print("could not update /etc/hosts:", e)


def start():
    ensure_hosts()
    key = crt = None
    try:
        key, crt = make_cert()
    except Exception as e:
        print("cert generation failed:", e)

    # panel ports only on the panel host; port 80 on each decoy address
    binds = [(PANEL_IP, p) for p in PORT_PAGES] + [(PANEL_IP, 80),
             (HOSTING_IP, 80), (PLAIN_IP, 80)]
    for ip, port in binds:
        try:
            srv = Threaded((ip, port), _handler_for(port))
            if port in TLS_PORTS and crt:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(crt, key)
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        except OSError as e:
            print(f"{ip}:{port} unavailable: {e}")
    time.sleep(1.0)


if __name__ == "__main__":
    start()
    print(f"Kumo panel lab — panels on {PANEL_IP}: "
          + ", ".join(str(p) for p in sorted(PORT_PAGES)))
    print(f"  decoys: hosting.panltest={HOSTING_IP}, plain.panltest={PLAIN_IP}")
    while True:
        time.sleep(3600)
