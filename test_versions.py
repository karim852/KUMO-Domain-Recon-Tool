"""
Live version-detection test: serve real HTTP responses advertising a spread of
PHP versions and check what Kumo concludes from each.

The unit cases in test_rules.py cover the comparison logic. This covers the
whole path end to end — real socket, real headers, real parsing — across every
PHP branch from 5.0 to 8.5, because a version rule that is right in a table and
wrong on the wire is still wrong.

Columns:
  php2shell  the runtime predates the 2026-10-21 fixes -> unpatched
  eol        the branch receives no security releases at all

    python3 test_versions.py
"""
import http.server
import socketserver
import threading
import warnings

warnings.filterwarnings("ignore")

import engine
import requests

HOST, PORT = "127.0.0.1", 8099
G = "\033[92m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

# (version string sent, php2shell expected, eol expected)
CASES = [
    # supported branches, patched — both rules must stay silent
    ("8.5.12", False, False),
    ("8.4.27", False, False),
    ("8.3.36", False, False),
    ("8.2.35", False, False),
    ("8.5.20", False, False),
    # supported branches, unpatched — php2shell only
    ("8.5.11", True,  False),
    ("8.4.26", True,  False),
    ("8.4.0",  True,  False),
    ("8.3.35", True,  False),
    ("8.3.0",  True,  False),
    ("8.2.34", True,  False),
    ("8.2.0",  True,  False),
    # end-of-life branches — both
    ("8.1.33", True, True),
    ("8.1.0",  True, True),
    ("8.0.30", True, True),
    ("8.0.0",  True, True),
    ("7.4.33", True, True),
    ("7.3.33", True, True),
    ("7.2.24", True, True),
    ("7.1.33", True, True),
    ("7.0.33", True, True),
    ("7.0.0",  True, True),
    ("5.6.40", True, True),
    ("5.5.38", True, True),
    ("5.4.45", True, True),
    ("5.4.0",  True, True),
    ("5.3.29", True, True),
    ("5.2.17", True, True),
    ("5.0.0",  True, True),
    # outside scope
    ("4.4.9",  False, False),
]

# How the version is advertised. Both header forms must work, and a suppressed
# version must produce nothing at all.
STYLES = {
    "x-powered-by": lambda v: {"X-Powered-By": f"PHP/{v}"},
    "server":       lambda v: {"Server": f"Apache/2.4.62 (Debian) PHP/{v}"},
}

_state = {"headers": {}}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (b"<!DOCTYPE html><html><head><title>Riverside Dental</title>"
                b"</head><body><h1>Riverside Dental</h1></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _state["headers"].items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    srv = Threaded((HOST, PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    rules = {r["id"]: r for r in engine.VULN_RULES}
    php2 = rules["php2shell-unpatched-php"]
    eol = rules["php-eol-runtime"]
    s2 = engine._rule_scrub(php2, HOST)
    se = engine._rule_scrub(eol, HOST)

    print(f"{B}Live PHP version detection{X}  —  {len(CASES)} versions × "
          f"{len(STYLES)} header styles, over real HTTP\n")
    print(f"  {'version':<10} {'style':<14} {'php2shell':<20} {'eol':<20}")
    print(f"  {'-'*10} {'-'*14} {'-'*20} {'-'*20}")

    fails = []
    for version, want_php2, want_eol in CASES:
        for style, build in STYLES.items():
            _state["headers"] = build(version)
            r = requests.get(f"http://{HOST}:{PORT}/", timeout=5)
            got2 = engine._eval_rule(r, php2, s2)
            gote = engine._eval_rule(r, eol, se)
            ok2, oke = got2 is want_php2, gote is want_eol
            if not ok2:
                fails.append((version, style, "php2shell", want_php2, got2))
            if not oke:
                fails.append((version, style, "eol", want_eol, gote))

            def cell(got, want, ok):
                mark = f"{G}ok{X}" if ok else f"{R}FAIL{X}"
                return f"{'HIT ' if got else 'none'} {mark}"
            print(f"  {version:<10} {style:<14} {cell(got2, want_php2, ok2):<29} "
                  f"{cell(gote, want_eol, oke):<29}")

    # A version that is present but unreadable must yield nothing.
    print()
    for label, hdrs in [("version suppressed", {"X-Powered-By": "PHP"}),
                        ("no PHP at all", {"Server": "nginx"}),
                        ("not PHP", {"X-Powered-By": "ASP.NET"})]:
        _state["headers"] = hdrs
        r = requests.get(f"http://{HOST}:{PORT}/", timeout=5)
        got2 = engine._eval_rule(r, php2, s2)
        gote = engine._eval_rule(r, eol, se)
        ok = not got2 and not gote
        if not ok:
            fails.append((label, "-", "silence", False, got2 or gote))
        print(f"  {label:<22} -> php2shell={got2!s:<6} eol={gote!s:<6} "
              f"{G + 'ok' + X if ok else R + 'FAIL' + X}")

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for v, style, which, want, got in fails:
            print(f"  {v} [{style}] {which}: wanted {want}, got {got}")
        return 1
    print(f"{G}every version classified correctly, both header styles, "
          f"and no version means no finding{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
