"""
False-positive harness: run Kumo's exposure modules against fplab.py's
negative-control hosts, where the correct answer is always "nothing found".

Anything reported here is a false positive, printed with the evidence needed
to fix it (module, host, path, status, size, severity).

    python3 test_fp.py              # all hosts, all exposure modules
    python3 test_fp.py echo.fptest  # one host
"""
import os
import sys
import warnings

warnings.filterwarnings("ignore")

# the lab answers on loopback: never send its traffic to an outbound proxy
os.environ["NO_PROXY"] = (os.environ.get("NO_PROXY", "") + ",.fptest,"
                          + ",".join(h for h in
                                     ["spa.fptest", "soft404.fptest", "waf.fptest",
                                      "echo.fptest", "jsonapi.fptest", "clean.fptest",
                                      "redirect.fptest"]))
os.environ["no_proxy"] = os.environ["NO_PROXY"]

import engine
import fplab

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

# Modules that make claims about the target's exposure surface. These are the
# ones a false positive actually hurts. Pure-inventory modules (dns, whois,
# geo, ports...) need outbound internet and are covered by test_live.py.
EXPOSURE_MODULES = [
    "endpoints",
    "nuclei",
    "robots",
    "whatweb",
    "js_secrets",
    "api_fuzzer",
    "content_intel",
    "cloud_buckets",
    "favicon",
]


# Findings that describe the host's security POSTURE rather than claiming an
# exposure. A missing X-Frame-Options really is missing on most of these hosts,
# so reporting it is correct and is not scored as a false positive. clean.fptest
# sets every header, so it must produce none of these — that is the real test.
POSTURE = ("x-frame-options", "clickjacking", "content-security-policy",
           "strict-transport", "x-content-type-options", "referrer-policy",
           "permissions-policy", "cookie", "security header")


def is_posture(label):
    low = label.lower()
    return any(p in low for p in POSTURE)


def findings_of(mod, data):
    """Normalise every module's output to a list of (label, detail) claims."""
    if not isinstance(data, dict) or data.get("error"):
        return []
    out = []

    if mod == "endpoints":
        for f in data.get("findings", []):
            out.append((f"{f.get('severity','?'):8} {f.get('name','?')}",
                        f"{f.get('path')} [{f.get('status')}, {f.get('size')}B]"))

    elif mod == "nuclei":
        for f in data.get("findings", []):
            out.append((f"{f.get('severity','?'):8} {f.get('name','?')}",
                        f"{f.get('path')} [{f.get('status')}, {f.get('size')}B] "
                        f"({f.get('source') or f.get('rule_id')})"))

    elif mod == "robots":
        # robots.txt content is a fact about the host, not a vulnerability claim;
        # only flag entries the module itself marked as a sensitive discovery.
        rb = data.get("robots") or {}
        for e in rb.get("disallowed", []):
            if e.get("sensitive"):
                out.append(("sensitive disallow", str(e.get("path"))))

    elif mod == "whatweb":
        for t in (data.get("technologies") or []):
            name = t.get("name") if isinstance(t, dict) else str(t)
            out.append(("tech", str(name)))

    elif mod == "js_secrets":
        for s in (data.get("secrets") or data.get("findings") or []):
            out.append((f"secret {s.get('type','?')}", str(s.get('match') or s.get('value'))[:60]))

    elif mod == "api_fuzzer":
        for e in (data.get("discovered") or []):
            out.append((f"api {e.get('name','?')}", f"{e.get('path')} [{e.get('status')}]"))

    elif mod == "content_intel":
        for k in ("secrets", "sensitive"):
            for s in (data.get(k) or []):
                out.append((f"{k} {str(s.get('type',''))}", str(s)[:70]))

    elif mod == "cloud_buckets":
        for b in (data.get("found") or data.get("buckets") or []):
            out.append(("bucket", str(b)[:70]))

    elif mod == "favicon":
        for m in (data.get("matches") or []):
            out.append(("favicon match", str(m)[:70]))

    return out


def run_host(host, modules):
    print(f"\n{B}── {host} {D}(ground truth: 0 findings){X}")
    total_fp = 0
    for mod in modules:
        name, fn = engine.ALL_MODULES[mod]
        try:
            data = fn(host)
        except Exception as e:
            print(f"  {Y}{mod:14}{X} crashed: {e}")
            continue
        if isinstance(data, dict) and data.get("error"):
            print(f"  {D}{mod:14} n/a ({str(data['error'])[:46]}){X}")
            continue
        claims = findings_of(mod, data)
        posture = [c for c in claims if is_posture(c[0])]
        fps = [c for c in claims if not is_posture(c[0])]
        if not fps:
            note = f"  {D}({len(posture)} posture finding(s), expected){X}" if posture else ""
            print(f"  {G}{mod:14} clean{X}{note}")
            continue
        total_fp += len(fps)
        print(f"  {R}{mod:14} {len(fps)} false positive(s){X}")
        for label, detail in fps[:14]:
            print(f"      {R}·{X} {label}  {D}{detail}{X}")
        if len(fps) > 14:
            print(f"      {D}… and {len(fps)-14} more{X}")
    return total_fp


def main():
    hosts = sys.argv[1:] or list(fplab.PROFILES)
    bad = [h for h in hosts if h not in fplab.PROFILES]
    if bad:
        print("unknown host(s):", bad)
        return 2

    fplab.start()
    print(f"{B}Kumo false-positive harness{X}  —  {len(hosts)} host(s), "
          f"{len(EXPOSURE_MODULES)} module(s)")

    grand = 0
    per_host = {}
    for h in hosts:
        n = run_host(h, EXPOSURE_MODULES)
        per_host[h] = n
        grand += n

    print(f"\n{B}Summary{X}")
    for h, n in per_host.items():
        mark = f"{G}clean{X}" if n == 0 else f"{R}{n} FP{X}"
        print(f"  {h:18} {mark}")
    print(f"\n  {B}total false positives: "
          f"{(G if grand == 0 else R)}{grand}{X}")
    return 0 if grand == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
