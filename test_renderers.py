"""
Execute every web-UI renderer against real module output.

This exists because a syntax check cannot catch what broke the ports card: the
renderer referenced an undefined variable (`d` instead of `data`), which is
valid JavaScript until it runs. `node --check` passed it. The dashboard then
showed the ports card stuck on its loading skeleton forever while the pill said
"done", because fillCard threw before it could clear the running state.

So each renderer is actually run, in Node, against output from the real engine,
and must return a string without throwing.

Requires node. Skips cleanly if it is missing.

    python3 test_renderers.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore")

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))


def extract_js():
    """Pull the dashboard's script block out of web.py."""
    src = open(os.path.join(HERE, "web.py"), encoding="utf-8").read()
    blocks = re.findall(r"<script>(.*?)</script>", src, re.S)
    if not blocks:
        return None
    js = "\n".join(blocks)
    # index() substitutes this placeholder at request time; stand in for it here.
    js = js.replace("__MODULES_JSON__", json.dumps({
        k: k for k in ["ports", "dns", "breachintel", "subdomains", "screenshot",
                       "geo", "whois", "ssl", "headers", "wafw00f", "whatweb",
                       "robots", "endpoints", "nuclei", "shodan", "censys",
                       "brute", "wayback", "email_harvest", "dorks", "osint",
                       "favicon", "cloud_buckets", "js_secrets", "content_intel",
                       "http_inspect", "api_fuzzer"]}))
    return js


# Payloads shaped like what the engine really returns, including the awkward
# cases: a CDN-fronted port scan (the one that broke), an error dict, and {}.
def payloads():
    return {
        "ports": {
            "open": [
                {"port": 80, "service": "HTTP (via cloudflare edge)", "risk": "info",
                 "source": "scan", "banner": "", "version": "", "edge": "cloudflare",
                 "confidence": "edge"},
                {"port": 443, "service": "HTTPS (via cloudflare edge)", "risk": "info",
                 "source": "scan", "banner": "", "version": "", "edge": "cloudflare",
                 "confidence": "edge"},
                {"port": 8443, "service": "HTTPS-Alt (via cloudflare edge)",
                 "risk": "info", "source": "scan", "banner": "", "version": "",
                 "edge": "cloudflare", "confidence": "edge"},
            ],
            "origin_open": [],
            "total_scanned": 96,
            "cdn": "cloudflare",
            "edge_ports": 3,
            "cdn_note": "uphold.com resolves to the cloudflare edge (104.16.0.1). "
                        "3 open port(s) belong to that edge.",
            "port_catchall": False, "catchall_note": "", "target_ip": "104.16.0.1",
            "results": [], "from_intel": 0,
        },
        # a non-CDN host, so the other branch of the same renderer runs too
        "ports_plain": {
            "open": [
                {"port": 22, "service": "SSH", "risk": "high", "source": "scan",
                 "banner": "SSH-2.0-OpenSSH_8.9p1", "version": "OpenSSH_8.9p1"},
                {"port": 3306, "service": "MySQL", "risk": "critical",
                 "source": "shodan_censys", "banner": "", "version": ""},
            ],
            "origin_open": [], "total_scanned": 96, "cdn": None, "edge_ports": 0,
            "cdn_note": "", "port_catchall": False, "catchall_note": "",
            "target_ip": "203.0.113.5", "results": [], "from_intel": 1,
        },
        "dns": {
            "ips": {"v4": ["203.0.113.5"], "v6": []},
            "records": {"MX": ["mail.example.com"], "TXT": ["v=spf1 -all"]},
            "email_security": {
                "spf": {"found": True, "policy": "-all (strict)", "valid": True,
                        "record_count": 1, "notes": [], "lookup_failed": False,
                        "record": "v=spf1 -all"},
                "dmarc": {"found": True, "policy": "reject (strict) — inherited from example.com",
                          "valid": True, "inherited": True, "found_at": "example.com",
                          "subdomain_policy": "", "pct": None, "rua": None,
                          "record_count": 1, "lookup_failed": False,
                          "notes": ["policy inherited from the organisational domain"]},
                "dkim": {"found": False, "selector": "", "selectors_found": [],
                         "revoked_selectors": [], "selectors_tried": 89,
                         "notes": ["none of 89 known selectors resolved"]},
                "mta_sts": {"found": True, "record": "v=STSv1; id=1"},
                "tls_rpt": {"found": False, "record": None},
                "bimi": {"found": False, "record": None},
                "grade": "B", "score": 6,
            },
        },
        "breachintel": {
            "domain": "example.com",
            "summary": {"total_infostealer_hits": 2, "total_employees_leaked": 1,
                        "total_clients_leaked": 0, "total_emails_found": 3,
                        "breach_names": ["LinkedIn"],
                        "critical_findings": [{"source": "hr", "type": "x", "detail": "y"}]},
            "sources": {
                "hudsonrock": {"status": "ok", "total_employees": 1, "total_clients": 0,
                               "third_parties": 0, "total_records": 1,
                               "stealer_families": {"RedLine": 1},
                               "antiviruses": {"total": 1, "found_pct": 50, "free_pct": 0,
                                               "list": [{"name": "Defender", "count": 1}]},
                               "employee_passwords": {"total": 1, "too_weak": 1},
                               "employee_urls": [{"url": "https://sso.example.com", "occurrence": 2}],
                               "client_urls": [], "third_party_domains": [],
                               "email_stealer_checks": []},
                "hr_per_email": {
                    "a@example.com": {"compromised": True, "date_compromised": "2026-01-01",
                                      "computer_name": "PC1", "operating_system": "Win11",
                                      "antiviruses": [], "top_passwords": ["x"],
                                      "total_corporate_services": 1, "total_user_services": 2,
                                      "count": 1},
                    "b@example.com": {"compromised": False},
                    "c@example.com": {"compromised": None, "status": "rate_limited"},
                },
                "hr_per_email_stats": {"emails_collected": 3, "emails_checked": 3,
                                       "emails_skipped": 0, "compromised": 1, "clean": 1,
                                       "unknown": 1,
                                       "sources": {"harvester": 3, "chiasmodon": 0,
                                                   "proxynova": 0}},
                "hibp": {"status": "ok", "domain_breaches": [
                    {"name": "LinkedIn", "title": "LinkedIn", "breach_date": "2012-05-05",
                     "pwn_count": 164611595, "data_classes": ["Email addresses"]}],
                    "total_known_breaches": 900},
                "chiasmodon": {"status": "ok", "employee_logins": []},
                "proxynova_comb": {"status": "ok", "total_count": 0, "parsed": [],
                                   "sample_passwords": []},
                "harvested_emails": ["a@example.com"],
                "company_domains": ["example.com"],
            },
            "api_keys_used": {"hibp": False, "chiasmodon": False},
        },
        "cms": {
            "cms": "wordpress", "cms_name": "WordPress", "confidence": "high",
            "detection_score": 12,
            "signals": ["generator meta (body)", "wp-content asset path (body)"],
            "candidates": {"wordpress": 12},
            "version": "6.4.2", "version_source": "/",
            "paths_probed": 14, "total_findings": 3,
            "severity_counts": {"critical": 1, "medium": 1, "low": 1},
            "findings": [
                {"name": "WordPress: wp-config backup", "severity": "critical",
                 "path": "/wp-config.php.bak", "status": 200, "size": 180,
                 "detail": "wp-config backup", "confidence": "confirmed"},
                {"name": "WordPress user enumeration via REST API", "severity": "medium",
                 "path": "/wp-json/wp/v2/users", "detail": "3 usernames",
                 "confidence": "confirmed"},
                {"name": "WordPress version disclosed", "severity": "low",
                 "path": "/", "detail": "WordPress 6.4.2",
                 "confidence": "version-inference"},
            ],
            "users": [{"id": 1, "name": "Dr Hannah Reed", "slug": "hannah"},
                      {"id": 2, "name": "Site Admin", "slug": "admin"}],
            "plugins": [{"name": "woocommerce", "version": "8.4.0"},
                        {"name": "contact-form-7", "version": "5.8.4"}],
            "themes": [{"name": "astra", "version": "4.6.0"}],
        },
        # the case that must render as "nothing found" rather than blank
        "cms_none": {
            "cms": None, "confidence": "none", "detection_score": 0,
            "signals": [], "candidates": {}, "version": None,
            "version_source": None, "findings": [], "users": [],
            "plugins": [], "themes": [], "paths_probed": 0,
            "severity_counts": {}, "note": "No CMS identified.",
        },
        "subdomains": {
            "total": 2, "alive_count": 1,
            "subdomains": ["www.example.com", "api.example.com"],
            "resolved": [{"subdomain": "www.example.com", "ip": "203.0.113.5",
                          "alive": True, "sensitive": False},
                         {"subdomain": "api.example.com", "ip": "-",
                          "alive": False, "sensitive": True}],
            "sensitive": [{"subdomain": "api.example.com", "ip": "-", "alive": False,
                           "sensitive": True}],
            "sources_used": ["crt.sh", "shodan-internetdb"],
            "sources_failed": [], "ct_total": 0, "ct_sensitive": [],
            "attribution": {"www.example.com": ["crt.sh"],
                            "api.example.com": ["shodan-internetdb"]},
            "source_counts": {"crt.sh": 1, "shodan-internetdb": 1},
            "shodan_new": 1,
        },
    }


def main():
    js = extract_js()
    if not js:
        print(f"{R}could not extract the dashboard script from web.py{X}")
        return 1
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
    except Exception:
        print(f"{Y}node not available — skipping renderer execution{X}")
        return 0

    # Minimal DOM so the renderers can run headless.
    shim = """
    const __el = () => ({
      style:{setProperty(){}}, classList:{add(){},remove(){},toggle(){},contains:()=>false},
      appendChild(){}, setAttribute(){}, getAttribute:()=>null, remove(){},
      insertBefore(){}, removeChild(){}, replaceChild(){}, cloneNode(){return __el();},
      getBoundingClientRect:()=>({top:0,left:0,width:0,height:0}),
      addEventListener(){}, querySelectorAll:()=>[], querySelector:()=>null,
      innerHTML:'', textContent:'', value:'', dataset:{}, focus(){}, click(){},
      scrollIntoView(){}, insertAdjacentHTML(){}, closest:()=>null,
    });
    const document = {
      documentElement: __el(), head: __el(), body: __el(),
      getElementById: () => __el(),
      querySelector: () => __el(),
      querySelectorAll: () => [],
      createElement: () => __el(),
      addEventListener(){},
    };
    const window = { _scanResults: {}, addEventListener(){}, matchMedia: () => ({matches:false, addEventListener(){}}),
                     location:{href:'', origin:''}, setTimeout, clearTimeout, setInterval, clearInterval };
    const navigator = { clipboard: { writeText: () => {} }, userAgent: 'node' };
    const localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
    const crypto = { randomUUID: () => 'x' };
    const fetch = () => Promise.resolve({ ok:true, json: async () => ({}), text: async () => '' });
    const EventSource = function(){ this.close=()=>{}; };
    const alert = () => {};
    """
    harness = """
    const __out = [];
    for (const [mod, payload] of Object.entries(__PAYLOADS__)) {
      const id = mod.replace(/_plain$/, '');
      for (const [label, data] of [['normal', payload], ['error', {error:'Module timed out after 60s'}], ['empty', {}]]) {
        try {
          const html = renderContent(id, data);
          const badges = getBadges(id, data);
          if (typeof html !== 'string') throw new Error('renderContent did not return a string');
          __out.push({mod, label, ok:true, len:html.length});
        } catch (e) {
          __out.push({mod, label, ok:false, err:String(e && e.message || e)});
        }
      }
    }
    console.log('@@RESULT@@' + JSON.stringify(__out));
    """
    code = shim + "\n" + js + "\n" + harness.replace("__PAYLOADS__", json.dumps(payloads()))

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(code)
        path = f.name
    try:
        p = subprocess.run(["node", path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(path)

    marker = "@@RESULT@@"
    line = next((l for l in p.stdout.splitlines() if l.startswith(marker)), None)
    if not line:
        print(f"{R}harness did not run{X}")
        print((p.stderr or p.stdout)[:1500])
        return 1

    results = json.loads(line[len(marker):])
    print(f"{B}Executing every renderer{X}  "
          f"{D}(normal payload, error dict, and empty object){X}\n")
    fails = [r for r in results if not r["ok"]]
    bymod = {}
    for r in results:
        bymod.setdefault(r["mod"], []).append(r)
    for mod, rows in bymod.items():
        bad = [r for r in rows if not r["ok"]]
        mark = f"{G}ok  {X}" if not bad else f"{R}FAIL{X}"
        detail = ", ".join(f"{r['label']}={r.get('len', r.get('err'))}" for r in rows)
        print(f"  {mark} {mod:16} {D}{detail[:90]}{X}")
        for r in bad:
            print(f"       {R}{r['label']}: {r['err']}{X}")

    print()
    if fails:
        print(f"{R}{len(fails)} renderer failure(s){X}")
        return 1
    print(f"{G}every renderer returns a string for real data, for an error dict "
          f"and for an empty object — no card can hang on its skeleton{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
