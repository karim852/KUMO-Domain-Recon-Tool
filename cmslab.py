"""
CMS lab — three CMS targets plus the look-alikes that must NOT match.

Serves, by Host header:

  wp.cmstest      WordPress with exposed wp-config backup, debug log,
                  reachable installer, REST user list, plugins and themes
  joomla.cmstest  Joomla with an exposed configuration backup and installer
  drupal.cmstest  Drupal with an exposed settings.php backup and installer
  blog.cmstest    a site that WRITES ABOUT WordPress but does not run it
  plain.cmstest   an ordinary site running no CMS at all

The last two are the point. "WordPress" appearing in page text is not evidence
that a site runs WordPress, and a scanner that treats it as such reports the
wrong CMS and then probes dozens of paths that cannot exist. blog.cmstest
mentions WordPress, Joomla and Drupal repeatedly in prose and must still be
reported as running none of them.

    python3 cmslab.py
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
VHOSTS = ["wp.cmstest", "joomla.cmstest", "drupal.cmstest",
          "blog.cmstest", "plain.cmstest", "magento.cmstest",
          "wpdone.cmstest"]

# ── WordPress ────────────────────────────────────────────────────────────
WP_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=4.6.0">
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.4.0">
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4"></script>
<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.2"></script>
<link rel="https://api.w.org/" href="/wp-json/" />
</head><body>
<h1>Northfield Dental</h1>
<img src="/wp-content/uploads/2026/01/clinic.jpg" alt="clinic">
<a href="/wp-login.php">Log in</a>
</body></html>"""

WP_ROUTES = {
    "/": (200, "text/html", WP_HOME),
    "/feed/": (200, "application/rss+xml",
               '<?xml version="1.0"?><rss version="2.0"><channel>'
               '<generator>https://wordpress.org/?v=6.4.2</generator>'
               '<title>Northfield Dental</title></channel></rss>'),
    "/wp-json/wp/v2/users": (200, "application/json", json.dumps([
        {"id": 1, "name": "Dr Hannah Reed", "slug": "hannah"},
        {"id": 2, "name": "Site Admin", "slug": "admin"},
        {"id": 3, "name": "Marc Webb", "slug": "marc"},
    ])),
    "/wp-config.php.bak": (200, "text/plain",
                           "<?php\ndefine('DB_NAME', 'northfield_wp');\n"
                           "define('DB_USER', 'wpuser');\n"
                           "define('DB_PASSWORD', 'S3cret-Prod-2026');\n"
                           "define('AUTH_KEY', 'q!8xZ...');\n"),
    "/wp-content/debug.log": (200, "text/plain",
                              "[06-Jan-2026 10:04:11 UTC] PHP Notice:  Undefined index: id in "
                              "/var/www/html/wp-content/plugins/woocommerce/cart.php on line 88\n"
                              "[06-Jan-2026 10:05:02 UTC] PHP Warning:  include() failed\n"
                              "Stack trace:\n#0 /var/www/html/wp-settings.php(point)\n"),
    "/wp-admin/install.php": (200, "text/html",
                              "<html><head><title>WordPress &rsaquo; Installation</title></head>"
                              "<body><h1>WordPress</h1><p>wp-admin installation</p></body></html>"),
    "/wp-cli.yml": (200, "text/plain", "path: /var/www/html\nurl: https://wp.cmstest\nuser: admin\n"),
    "/xmlrpc.php": (200, "text/plain",
                    "XML-RPC server accepts POST requests only."),
    "/wp-content/plugins/": (200, "text/html",
                             "<html><head><title>Index of /wp-content/plugins</title></head><body>"
                             "<h1>Index of /wp-content/plugins</h1><a href='../'>Parent Directory</a>"
                             "<a href='woocommerce/'>woocommerce/</a></body></html>"),
    "/wp-content/plugins/woocommerce/readme.txt": (200, "text/plain",
                                                   "=== WooCommerce ===\nStable tag: 8.4.0\n"),
    "/wp-content/plugins/contact-form-7/readme.txt": (200, "text/plain",
                                                      "=== Contact Form 7 ===\nStable tag: 5.8.4\n"),
    "/wp-content/themes/astra/style.css": (200, "text/css",
                                           "/*\nTheme Name: Astra\nVersion: 4.6.0\n*/\n"),
}

# ── Joomla ───────────────────────────────────────────────────────────────
JOOMLA_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="generator" content="Joomla! - Open Source Content Management" />
<link rel="stylesheet" href="/media/system/css/joomla-fontawesome.min.css">
<script src="/media/system/js/core.min.js"></script>
<link rel="stylesheet" href="/templates/cassiopeia/css/template.css">
</head><body>
<h1>Riverside Sailing Club</h1>
<a href="/index.php?option=com_contact&view=contact&id=1">Contact us</a>
</body></html>"""

JOOMLA_ROUTES = {
    "/": (200, "text/html", JOOMLA_HOME),
    "/administrator/manifests/files/joomla.xml": (200, "application/xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n<extension type="file" method="upgrade">\n'
        '  <name>files_joomla</name>\n  <version>4.2.7</version>\n'
        '  <creationDate>2026-01-05</creationDate>\n</extension>\n'),
    "/configuration.php.bak": (200, "text/plain",
                               "<?php\nclass JConfig {\n"
                               "  public $host = 'localhost';\n"
                               "  public $user = 'joomla_rw';\n"
                               "  public $password = 'R1ver-s1de!';\n"
                               "  public $db = 'riverside';\n}\n"),
    "/installation/": (200, "text/html",
                       "<html><head><title>Joomla! Web Installer</title></head>"
                       "<body>Installation step 1</body></html>"),
    "/administrator/": (200, "text/html",
                        "<html><head><title>Administration - Riverside</title></head>"
                        "<body><form action='index.php'><input name='username'>"
                        "<input name='passwd' type='password'></form></body></html>"),
}

# ── Drupal ───────────────────────────────────────────────────────────────
DRUPAL_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="generator" content="Drupal 9 (https://www.drupal.org)" />
<link rel="stylesheet" href="/core/themes/olivero/css/base/base.css">
<script src="/core/misc/drupal.js"></script>
<link rel="stylesheet" href="/sites/default/files/css/css_x1.css">
</head><body class="path-node node--type-article">
<h1>Fenwick County Library</h1>
<script type="application/json" data-drupal-selector="drupal-settings-json">{"path":{}}</script>
</body></html>"""

DRUPAL_ROUTES = {
    "/": (200, "text/html", DRUPAL_HOME),
    "/CHANGELOG.txt": (200, "text/plain",
                       "Drupal 9.5.11, 2026-01-05\n-------------------------\n"
                       "- Fixed security issues.\n"),
    "/sites/default/settings.php.bak": (200, "text/plain",
                                        "<?php\n$databases['default']['default'] = array(\n"
                                        "  'database' => 'fenwick_drupal',\n"
                                        "  'username' => 'drupal',\n"
                                        "  'password' => 'Fenw1ck-DB!',\n);\n"),
    "/core/install.php": (200, "text/html",
                          "<html><head><title>Choose language | Drupal</title></head>"
                          "<body>Drupal install</body></html>"),
    "/user/register": (200, "text/html",
                       "<html><head><title>Create new account | Fenwick</title></head>"
                       "<body><form>Create new account</form></body></html>"),
}

# ── The decoys ───────────────────────────────────────────────────────────
# A site that writes about CMS platforms. Every product name appears in the
# text; none of the structural signals do.
BLOG_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="generator" content="Hugo 0.121.0" />
<title>CMS Weekly — comparing WordPress, Joomla and Drupal</title>
<link rel="stylesheet" href="/assets/css/main.css">
</head><body>
<h1>Is WordPress still the right choice in 2026?</h1>
<p>We compared WordPress, Joomla and Drupal across security, plugins and
hosting cost. WordPress still leads on plugin availability, while Drupal
remains the pick for complex editorial workflows and Joomla sits in between.
Readers often ask whether a WordPress migration is worth it, or whether a
Joomla site should move to Drupal instead.</p>
<p>Our WordPress security checklist covers wp-config hardening, disabling
XML-RPC, and keeping plugins current. For Drupal we cover settings.php
permissions, and for Joomla the administrator directory.</p>

<!-- The paragraphs below exist to break fingerprinting that matches product
     names in page text. Every brand here is written the way its own marketing
     writes it, bang included, and the headers are quoted the way a technical
     article quotes them. A site that reports any of this as installed
     software is reading prose as evidence. -->
<p>Joomla! 5.1 shipped in March. Joomla! remains the only one of the three
with a built-in ACL editor. Magento (now Adobe Commerce) and PrestaShop
cover retail, while Webflow and Squarespace suit agencies. Typo3, MODX,
Ghost and OpenCart round out the field.</p>
<p>On the infrastructure side we put Cloudflare in front of everything, with
Fastly for video. If you are debugging a cache miss, check the
<code>cf-ray</code> and <code>cf-cache-status</code> response headers, or
<code>X-Amz-Cf-Id</code> on CloudFront. Netlify and Vercel set their own:
look for <code>x-nf-request-id</code> and <code>x-vercel-id</code>.</p>
<p>For WAFs, Sucuri stamps <code>x-sucuri-id</code> on every response and
Imperva sets an <code>incap_ses</code> cookie. We also tested
<code>X-Powered-By: Express</code> fingerprinting and found it unreliable.</p>

<a href="/articles/wordpress-security">More on WordPress security</a>
<a href="/articles/drupal-vs-joomla">Drupal vs Joomla</a>
</body></html>"""

PLAIN_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Halvorsen Engineering</title>
<link rel="stylesheet" href="/static/css/site.css">
<script src="/static/js/app.js"></script>
</head><body><h1>Halvorsen Engineering</h1>
<p>Precision components since 1974.</p></body></html>"""

# A real storefront on a platform Kumo fingerprints but has no deep checks
# for. The point of this host is that a blank result would be a lie: there IS
# a CMS here, Kumo just cannot go deep on it, and it has to say which.
MAGENTO_HOME = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Brightwater Supply</title>
<link rel="stylesheet" href="/skin/frontend/rwd/default/css/styles.css">
<script src="/js/mage/cookies.js"></script>
<script>var BLANK_URL = 'js/blank.html';
Mage.Cookies.path = '/';</script>
</head><body>
<h1>Brightwater Supply</h1>
<p>Industrial filtration, shipped same day.</p>
<form action="/checkout/cart/add/" method="post"><button>Add to cart</button></form>
</body></html>"""

# ── a correctly set-up WordPress ─────────────────────────────────────────
# These are the REAL pages WordPress 6.7.10 serves once it is installed,
# captured from a live install rather than written by hand. All three answer
# 200, and all three are refusals: the installer says it has already run, and
# database repair says it is switched off unless wp-config enables it.
#
# A check that only looks at the status code reports an exposed installer
# (critical) and an exposed repair page (high) on a stock site with nothing
# wrong with it. Both were reported, until a real install was scanned. This
# host exists so that cannot come back.
WP_ALREADY_INSTALLED = """<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &rsaquo; Installation</title>
	<link rel='stylesheet' id='dashicons-css' href='http://wplive.test/wp-includes/css/dashicons.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='buttons-css' href='http://wplive.test/wp-includes/css/buttons.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='forms-css' href='http://wplive.test/wp-admin/css/forms.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='l10n-css' href='http://wplive.test/wp-admin/css/l10n.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='install-css' href='http://wplive.test/wp-admin/css/install.min.css?ver=6.7.10' media='all' />
</head>
<body class="wp-core-ui">
<p id="logo">WordPress</p>

	<h1>Already Installed</h1><p>You appear to have already installed WordPress. To reinstall please clear your old database tables first.</p><p class="step"><a href="http://wplive.test/wp-login.php">Log In</a></p></body></html>"""

WP_REPAIR_DISABLED = """<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="robots" content="noindex,nofollow" />
	<title>WordPress &rsaquo; Database Repair</title>
	<link rel='stylesheet' id='dashicons-css' href='http://wplive.test/wp-includes/css/dashicons.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='buttons-css' href='http://wplive.test/wp-includes/css/buttons.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='forms-css' href='http://wplive.test/wp-admin/css/forms.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='l10n-css' href='http://wplive.test/wp-admin/css/l10n.min.css?ver=6.7.10' media='all' />
<link rel='stylesheet' id='install-css' href='http://wplive.test/wp-admin/css/install.min.css?ver=6.7.10' media='all' />
</head>
<body class="wp-core-ui">
<p id="logo"><a href="https://wordpress.org/">WordPress</a></p>

<h1 class="screen-reader-text">Allow automatic database repair</h1><p>To allow use of this page to automatically repair database problems, please add the following line to your <code>wp-config.php</code> file. Once this line is added to your config, reload this page.</p><p><code>define('WP_ALLOW_REPAIR', true);</code></p><h2 class="screen-reader-text">Check secret keys</h2><p>While you are editing your <code>wp-config.php</code> file, take a moment to make sure you have all 8 keys and that they are unique. You can generate these using the <a href="https://api.wordpress.org/secret-key/1.1/salt/">WordPress.org secret key service</a>.</p></body>
</html>
"""

WPDONE_ROUTES = {
    "/": (200, "text/html", WP_HOME),
    "/wp-admin/install.php": (200, "text/html", WP_ALREADY_INSTALLED),
    "/wp-admin/maint/repair.php": (200, "text/html", WP_REPAIR_DISABLED),
}

PROFILES = {
    "wpdone.cmstest": WPDONE_ROUTES,
    "magento.cmstest": {"/": (200, "text/html", MAGENTO_HOME)},
    "wp.cmstest": WP_ROUTES,
    "joomla.cmstest": JOOMLA_ROUTES,
    "drupal.cmstest": DRUPAL_ROUTES,
    "blog.cmstest": {"/": (200, "text/html", BLOG_HOME)},
    "plain.cmstest": {"/": (200, "text/html", PLAIN_HOME)},
}

# Ground truth for the harness.
EXPECTED_CMS = {
    "wp.cmstest": "wordpress",
    "joomla.cmstest": "joomla",
    "drupal.cmstest": "drupal",
    "blog.cmstest": None,
    "plain.cmstest": None,
    # fingerprinted as Magento, but not one of the three with deep checks
    "magento.cmstest": None,
    # a properly installed WordPress: detected, but nothing to report
    "wpdone.cmstest": "wordpress",
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _respond(self, head=False):
        path = self.path.split("?")[0]
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        routes = PROFILES.get(host)
        if routes is None:
            self.send_response(421)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in routes:
            code, ctype, body = routes[path]
        else:
            # honest 404, with a little size variance so it is not mistaken
            # for a uniform catch-all
            pad = int(hashlib.md5(path.encode()).hexdigest()[:4], 16) % 200
            code, ctype = 404, "text/html"
            body = ("<!DOCTYPE html><html><head><title>Not Found</title></head>"
                    "<body><h1>404</h1>" + ("<p>.</p>" * (pad // 8)) + "</body></html>")
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if host == "wp.cmstest":
            self.send_header("X-Pingback", "https://wp.cmstest/xmlrpc.php")
        if host == "drupal.cmstest":
            self.send_header("X-Generator", "Drupal 9 (https://www.drupal.org)")
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


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_cert():
    key, crt = "/tmp/cmslab.key", "/tmp/cmslab.crt"
    if not os.path.exists(crt):
        san = ",".join(f"DNS:{h}" for h in VHOSTS) + ",IP:127.0.0.1"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", crt, "-days", "365", "-nodes",
             "-subj", "/C=US/ST=Test/L=Test/O=Kumo CMS Lab/CN=cmstest",
             "-addext", f"subjectAltName={san}"],
            check=True, capture_output=True)
    return key, crt


def ensure_hosts():
    try:
        current = open("/etc/hosts").read()
        missing = [h for h in VHOSTS if h not in current]
        if missing:
            with open("/etc/hosts", "a") as f:
                f.write("\n# kumo cms lab\n127.0.0.1 " + " ".join(missing) + "\n")
    except Exception as e:
        print("could not update /etc/hosts:", e)


def start():
    ensure_hosts()
    srv = Threaded((HOST, 80), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        key, crt = make_cert()
        tls = Threaded((HOST, 443), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
    except Exception as e:
        print("TLS listener failed:", e)
    time.sleep(0.8)


if __name__ == "__main__":
    start()
    print("Kumo CMS lab on 80/443 for: " + ", ".join(VHOSTS))
    while True:
        time.sleep(3600)
