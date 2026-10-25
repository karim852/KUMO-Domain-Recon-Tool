"""
Subdomain source tests, with the focus on Shodan InternetDB.

InternetDB answers per IP, and its `hostnames` list belongs to the ADDRESS, not
to the target domain. On shared hosting, or behind a CDN, one address serves
many customers, so that list routinely contains other people's hostnames.
Feeding it in unfiltered would put strangers' domains into the operator's
subdomain list and present them as findings.

So the question these tests answer is not "did we find more subdomains" but
"did anything that is not the target's leak in".

    python3 test_subdomain_sources.py
"""
import json
import warnings

warnings.filterwarnings("ignore")

import engine

G = "\033[92m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

DOMAIN = "acme-corp.com"

# What a CDN or shared-hosting IP realistically reports: a couple of the
# target's names alongside a pile of other tenants.
SHARED_IP_HOSTNAMES = [
    "www.acme-corp.com",
    "api.acme-corp.com",
    "mail.acme-corp.com",
    # other tenants on the same address — must never appear
    "shop.othercompany.com",
    "blog.somebodyelse.net",
    "cdn.cloudflare.net",
    "unrelated.example.org",
    # lookalikes designed to slip past a sloppy suffix check
    "acme-corp.com.evil.net",
    "notacme-corp.com",
    "evil-acme-corp.com",
    # the apex itself is not a subdomain
    "acme-corp.com",
    # formatting noise
    "*.acme-corp.com",
    "UPPER.ACME-CORP.COM",
    "trailing.acme-corp.com.",
]

FOREIGN = {"shop.othercompany.com", "blog.somebodyelse.net", "cdn.cloudflare.net",
           "unrelated.example.org", "acme-corp.com.evil.net", "notacme-corp.com",
           "evil-acme-corp.com"}


class FakeResp:
    def __init__(self, payload):
        self._p = payload
        self.text = json.dumps(payload)
        self.status_code = 200

    def json(self):
        return self._p


def stub(hostnames, ips=("203.0.113.10",), fail=False):
    """Stub resolve() and req() so only InternetDB answers."""
    def fake_resolve(d):
        return {"v4": list(ips), "v6": []}

    def fake_req(url, **kw):
        if "internetdb.shodan.io" in url:
            if fail:
                return None
            return FakeResp({"ip": url.rsplit("/", 1)[-1], "ports": [80, 443],
                             "hostnames": list(hostnames), "tags": [],
                             "cpes": [], "vulns": []})
        return None            # every other source unavailable

    return fake_resolve, fake_req


def run_internetdb(hostnames, ips=("203.0.113.10",), fail=False, domain=DOMAIN):
    real_resolve, real_req = engine.resolve, engine.req
    engine.resolve, engine.req = stub(hostnames, ips, fail)
    try:
        return engine._shodan_internetdb_hostnames(domain)
    finally:
        engine.resolve, engine.req = real_resolve, real_req


def run_full(hostnames, domain=DOMAIN):
    """Full scan_subdomains with only InternetDB answering."""
    real_resolve, real_req = engine.resolve, engine.req
    real_crt = engine.scan_crtsh
    import socket as _s
    real_gai = _s.getaddrinfo
    engine.resolve, engine.req = stub(hostnames)
    engine.scan_crtsh = lambda d: {"total": 0, "subdomains": [], "sensitive": []}
    _s.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("no dns"))
    try:
        return engine.scan_subdomains(domain)
    finally:
        engine.resolve, engine.req = real_resolve, real_req
        engine.scan_crtsh = real_crt
        _s.getaddrinfo = real_gai


def main():
    fails = []

    def check(label, ok, detail=""):
        if not ok:
            fails.append(label)
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {label}"
              + (f"  {D}{detail}{X}" if detail else ""))

    print(f"{B}InternetDB hostname extraction{X}")
    names, status = run_internetdb(SHARED_IP_HOSTNAMES)
    check("status ok", status == "ok", status)
    check("target subdomains extracted",
          {"www.acme-corp.com", "api.acme-corp.com", "mail.acme-corp.com"} <= names,
          f"{len(names)} names")

    leaked = names & FOREIGN
    check("NO other tenant's hostname leaked in", not leaked,
          f"leaked={sorted(leaked)}" if leaked else "none")
    check("lookalike acme-corp.com.evil.net rejected",
          "acme-corp.com.evil.net" not in names)
    check("lookalike evil-acme-corp.com rejected",
          "evil-acme-corp.com" not in names)
    check("lookalike notacme-corp.com rejected",
          "notacme-corp.com" not in names)
    check("apex itself is not listed as a subdomain",
          DOMAIN not in names)
    check("wildcard entry normalised, not stored as *.",
          "*.acme-corp.com" not in names)
    check("uppercase normalised to lowercase",
          "upper.acme-corp.com" in names, sorted(names))
    check("trailing dot stripped",
          "trailing.acme-corp.com" in names)

    print(f"\n{B}Failure handling{X}")
    n2, s2 = run_internetdb(SHARED_IP_HOSTNAMES, fail=True)
    check("unreachable InternetDB reports error, not empty success",
          s2 == "error" and not n2, s2)

    real_resolve = engine.resolve
    engine.resolve = lambda d: {"v4": [], "v6": []}
    try:
        n3, s3 = engine._shodan_internetdb_hostnames(DOMAIN)
    finally:
        engine.resolve = real_resolve
    check("unresolvable domain reports no_ips", s3 == "no_ips", s3)

    print(f"\n{B}Wired into scan_subdomains{X}")
    res = run_full(SHARED_IP_HOSTNAMES)
    subs = set(res["subdomains"])
    check("shodan-internetdb listed as a source used",
          "shodan-internetdb" in res["sources_used"], str(res["sources_used"]))
    check("target subdomains present in the result",
          {"www.acme-corp.com", "api.acme-corp.com"} <= subs, f"{len(subs)} subs")
    check("NO foreign hostname in the final subdomain list",
          not (subs & FOREIGN), f"leaked={sorted(subs & FOREIGN)}")
    check("every name attributed to a source",
          all(res["attribution"].get(s) for s in subs))
    check("shodan names attributed to shodan-internetdb",
          res["attribution"].get("www.acme-corp.com") == ["shodan-internetdb"],
          str(res["attribution"].get("www.acme-corp.com")))
    check("source_counts reports the shodan contribution",
          res["source_counts"].get("shodan-internetdb", 0) >= 3,
          str(res["source_counts"]))
    check("shodan_new counts names this source added",
          res["shodan_new"] >= 3, str(res["shodan_new"]))
    check("sensitive prefixes still flagged (api, mail)",
          any(r["subdomain"].startswith(("api.", "mail.")) for r in res["resolved"]))

    print(f"\n{B}A clean IP adds nothing{X}")
    res2 = run_full(["shop.othercompany.com", "cdn.cloudflare.net"])
    check("foreign-only hostnames yield zero subdomains",
          not set(res2["subdomains"]), str(res2["subdomains"]))
    check("source still recorded as reachable",
          "shodan-internetdb" in res2["sources_used"])

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for f in fails:
            print("  -", f)
        return 1
    print(f"{G}InternetDB adds the target's own subdomains and nothing else — "
          f"no other tenant on a shared or CDN address can leak in{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
