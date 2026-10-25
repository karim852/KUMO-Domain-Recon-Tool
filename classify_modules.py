"""
Classify every Kumo module as passive or active, by observation.

Reading the source is not reliable here: scan_nuclei looks passive because its
probing lives in a helper, and scan_robots looks passive because the fetch is a
one-liner. So each module is actually run against a local target and every
outbound connection it makes is recorded. A module is ACTIVE if it contacts the
target itself; passive if it only talks to third parties.

Why this matters: passive modules touch nothing belonging to the target and are
safe to run at any scale, including against programs whose scope you have not
confirmed. Active modules send traffic that lands in the target's logs and need
the asset to be in scope of a program you are authorised to test.

    python3 classify_modules.py
"""
import json
import socket
import warnings

warnings.filterwarnings("ignore")

import engine
import lab

TARGET = "kumo-lab.test"
TARGET_IPS = {"127.0.0.1"}

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

contacted = []


def instrument():
    """Record every host each module reaches for, via requests and raw sockets."""
    real_req_get = engine.requests.get
    real_req_req = engine.requests.request
    real_conn = socket.socket.connect
    real_conn_ex = socket.socket.connect_ex
    real_gai = socket.getaddrinfo
    real_create = socket.create_connection

    def host_of(url):
        try:
            from urllib.parse import urlparse
            return (urlparse(url).hostname or "").lower()
        except Exception:
            return ""

    def wrap_get(url, *a, **k):
        contacted.append(host_of(url))
        return real_req_get(url, *a, **k)

    def wrap_request(method, url, *a, **k):
        contacted.append(host_of(url))
        return real_req_req(method, url, *a, **k)

    def wrap_connect(self, addr):
        try:
            contacted.append(str(addr[0]).lower())
        except Exception:
            pass
        return real_conn(self, addr)

    def wrap_connect_ex(self, addr):
        try:
            contacted.append(str(addr[0]).lower())
        except Exception:
            pass
        return real_conn_ex(self, addr)

    def wrap_create(addr, *a, **k):
        try:
            contacted.append(str(addr[0]).lower())
        except Exception:
            pass
        return real_create(addr, *a, **k)

    engine.requests.get = wrap_get
    engine.requests.request = wrap_request
    socket.socket.connect = wrap_connect
    socket.socket.connect_ex = wrap_connect_ex
    socket.create_connection = wrap_create
    # engine.req() wraps requests.get, so it is covered already.


def main():
    lab.start()
    instrument()

    print(f"{B}Observing what each module connects to{X}  "
          f"{D}(target: {TARGET} -> 127.0.0.1){X}\n")
    print(f"  {'module':16}{'class':9}{'target hits':12}third parties")
    print("  " + "-" * 74)

    results = {}
    for key, (desc, fn) in engine.ALL_MODULES.items():
        contacted.clear()
        try:
            fn(TARGET)
        except Exception:
            pass
        hosts = [h for h in contacted if h]
        target_hits = [h for h in hosts if h == TARGET or h in TARGET_IPS]
        third = sorted({h for h in hosts if h != TARGET and h not in TARGET_IPS})
        cls = "ACTIVE" if target_hits else "passive"
        results[key] = {"class": cls, "target_hits": len(target_hits),
                        "third_parties": third}
        colour = R if cls == "ACTIVE" else G
        tp = ", ".join(third[:3]) + (f" +{len(third)-3}" if len(third) > 3 else "")
        print(f"  {key:16}{colour}{cls:9}{X}{len(target_hits):<12}{D}{tp[:44]}{X}")

    active = [k for k, v in results.items() if v["class"] == "ACTIVE"]
    passive = [k for k, v in results.items() if v["class"] == "passive"]

    print("  " + "-" * 74)
    print(f"\n  {G}PASSIVE ({len(passive)}){X} — contact the target not at all, "
          f"safe to run at any scale:")
    print(f"    {', '.join(sorted(passive))}")
    print(f"\n  {R}ACTIVE ({len(active)}){X} — send traffic to the target and "
          f"land in its logs;")
    print(f"    run only against assets in scope of a program you are "
          f"authorised to test:")
    print(f"    {', '.join(sorted(active))}")

    with open("docs/module-classification.json", "w") as f:
        json.dump({"passive": sorted(passive), "active": sorted(active),
                   "detail": results}, f, indent=2)
    print(f"\n  written to docs/module-classification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
