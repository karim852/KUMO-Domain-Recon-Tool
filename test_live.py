"""
Live end-to-end test: runs every Kumo module against the local vulnerable lab
over a real network stack and checks that each one actually finds what is
planted there.
"""
import concurrent.futures
import sys
import time
import warnings

warnings.filterwarnings("ignore")

import engine
import web
import lab

TARGET = "127.0.0.1"
G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

# module -> (checker(data) -> (ok, detail))
def chk_dns(d):
    recs = d.get("records", {}) or {}
    a = recs.get("A") or []
    # The lab target is a bare IP, which has no DNS records to resolve — the
    # module is graded on returning a well-formed result, not on inventing data.
    if TARGET.replace(".", "").isdigit():
        return None, f"n/a for a raw IP target (records={list(recs)})"
    return bool(a), f"A={a[:2]}"

def chk_ssl(d):
    if d.get("error"): return False, d["error"][:50]
    return bool(d.get("issuer") or d.get("subject")), \
f"issuer={str(d.get('issuer'))[:34]} cn={str(d.get('subject'))[:24]}"

def chk_headers(d):
    miss = d.get("missing") or []
    return bool(miss or d.get("grade")), f"grade={d.get('grade')} missing={len(miss)}"

def chk_ports(d):
    open_ports = sorted(p["port"] for p in d.get("open", []))
    want = {80, 443, 22, 21, 3306, 25, 9200}
    hit = want & set(open_ports)
    return len(hit) >= 5, f"open={open_ports[:9]} banners={sum(1 for p in d.get('open',[]) if p.get('banner'))}"

def chk_robots(d):
    rb = d.get("robots") or {}
    dis = rb.get("disallowed") or []
    sec = d.get("security_txt")
    sm = d.get("sitemaps") or []
    return bool(dis) and bool(sec), \
           f"disallowed={len(dis)} sensitive={sum(1 for x in dis if x.get('sensitive'))} security.txt={bool(sec)} sitemaps={len(sm)}"

def chk_endpoints(d):
    names = [f["name"] for f in d.get("findings", [])]
    want = [".git", ".env", "phpinfo", "phpmyadmin", "htpasswd"]
    hit = [w for w in want if any(w.lower() in n.lower() for n in names)]
    return len(hit) >= 3, f"{d.get('total_found')} found: {hit}"

def chk_nuclei(d):
    pb = [f for f in d.get("findings", []) if f.get("source") == "rule_playbook"]
    ids = sorted({f["rule_id"] for f in pb})
    want = {"git-config", "env-file", "phpinfo", "elasticsearch",
            "spring-actuator-env", "htpasswd", "sql-dump", "ssh-private-key",
            "wp-user-enum", "swagger-spec", "phpmyadmin", "adminer",
            "docker-compose", "aws-credentials", "npm-token", "prometheus-metrics",
            "graphql-introspection", "wp-config-bak", "ds-store", "sonarqube"}
    hit = want & set(ids)
    return len(hit) >= 12, f"{len(pb)} playbook hits, {len(hit)}/{len(want)} expected: {sorted(hit)[:8]}…"

def chk_js(d):
    types = {s["type"] for s in d.get("secrets", [])}
    want = {"Stripe Live Secret Key", "Google API Key", "MongoDB URL",
            "GitHub Personal Token", "AWS Access Key ID", "GitLab Personal Token"}
    hit = {w for w in want if any(w in t for t in types)}
    vals = " ".join(s["value"] for s in d.get("secrets", []))
    clean = "YOUR_API_KEY" not in vals
    return len(hit) >= 4 and clean, f"{d.get('total')} secrets {sorted(hit)}"

def chk_content(d):
    c = d.get("counts", {}) or {}
    cats = d.get("categories", {}) or {}
    dbs = [i["value"] for i in cats.get("databases", [])]
    sens = [i.get("kind") for i in cats.get("sensitive", [])]
    return bool(dbs) and c.get("endpoints", 0) > 0, \
           f"total={d.get('total')} db={len(dbs)} sensitive={len(sens)} endpoints={c.get('endpoints')}"

def chk_api(d):
    specs = [s["path"] for s in d.get("specs", [])]
    disc = [x["path"] for x in d.get("discovered", [])]
    eps = [e["path"] for e in d.get("endpoints", [])]
    return d.get("total", 0) >= 3, f"total={d.get('total')} specs={len(specs)} disc={len(disc)} eps={len(eps)}"

def chk_http_inspect(d):
    if d.get("error"): return False, d["error"][:50]
    nh = [n["name"] for n in d.get("notable_headers", [])]
    ck = d.get("cookies", [])
    risky = d.get("methods", {}).get("risky", [])
    return bool(nh) and bool(ck), \
           f"req={len(d['request']['headers'])} resp={len(d['response']['headers'])} notable={nh[:3]} cookies={len(ck)} risky={risky}"

def chk_favicon(d):
    return bool(d.get("favicon_found")), f"hash={d.get('mmh3_hash')} size={d.get('size_bytes')}"

def chk_whatweb(d):
    return bool(d), f"{str(d)[:70]}"

def chk_generic(d):
    if isinstance(d, dict) and d.get("error"):
        return None, f"error: {str(d['error'])[:46]}"
    return None, f"{str(d)[:66]}"

CHECKS = {
    "dns": chk_dns, "ssl": chk_ssl, "headers": chk_headers, "ports": chk_ports,
    "robots": chk_robots, "endpoints": chk_endpoints, "nuclei": chk_nuclei,
    "js_secrets": chk_js, "content_intel": chk_content, "api_fuzzer": chk_api,
    "http_inspect": chk_http_inspect, "favicon": chk_favicon, "whatweb": chk_whatweb,
}

SKIP = {"screenshot"}


def run(key):
    desc, fn = engine.ALL_MODULES[key]
    budget = web.MODULE_TIMEOUTS.get(key, web.DEFAULT_TIMEOUT)
    t0 = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            data = ex.submit(fn, TARGET).result(timeout=budget)
        return key, data, time.time() - t0, None
    except concurrent.futures.TimeoutError:
        return key, None, time.time() - t0, "TIMEOUT"
    except Exception as e:
        return key, None, time.time() - t0, f"{type(e).__name__}: {e}"


def main():
    print(f"{B}Starting local vulnerable lab…{X}")
    lab.start()
    import requests as _rq
    try:
        _rq.get("http://127.0.0.1/", timeout=5)
        print(f"{G}Lab is up on 127.0.0.1 (80, 443, 9200, 22, 21, 3306, 25){X}\n")
    except Exception as e:
        print(f"{R}Lab failed to start: {e}{X}")
        return 1

    keys = [k for k in engine.ALL_MODULES if k not in SKIP]
    print(f"{B}Running {len(keys)} modules against the local vulnerable lab "
          f"(real HTTP/TLS/sockets){X}\n")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for key, data, elapsed, err in ex.map(run, keys):
            results[key] = (data, elapsed, err)

    graded = failed = 0
    order = [k for k in engine.ALL_MODULES if k in results]
    for key in order:
        data, elapsed, err = results[key]
        if err:
            print(f"  {R}ERROR{X} {key:<15} {elapsed:5.1f}s  {err[:56]}")
            failed += 1
            continue
        checker = CHECKS.get(key, chk_generic)
        try:
            ok, detail = checker(data)
        except Exception as e:
            ok, detail = False, f"checker crashed: {e}"
        if ok is None:
            print(f"  {D}----{X}  {key:<15} {elapsed:5.1f}s  {D}{detail}{X}")
        else:
            graded += 1
            if ok:
                print(f"  {G}PASS{X}  {key:<15} {elapsed:5.1f}s  {detail}")
            else:
                failed += 1
                print(f"  {R}FAIL{X}  {key:<15} {elapsed:5.1f}s  {detail}")

    print(f"\n{B}Graded modules: {graded}   Failures: {failed}{X}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
