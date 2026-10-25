"""
Control panel module tests.

Two questions. Does it find a real panel on its real port, and does it stay
quiet on a web hosting company's own website?

The second one is the trap. A hosting provider's marketing page says "cPanel
Login", "WHM Login", "Login to Webmin" and "Plesk Obsidian" in plain prose,
because that is what they sell. A scanner matching the product name would
report four control panels on every hosting company on the internet.

    python3 test_panels.py
"""
import os
import warnings

warnings.filterwarnings("ignore")

os.environ["NO_PROXY"] = (os.environ.get("NO_PROXY", "")
                          + ",.panltest,panel.panltest,hosting.panltest,plain.panltest,127.0.0.1,localhost")
os.environ["no_proxy"] = os.environ["NO_PROXY"]

import engine
import panellab

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"


def main():
    panellab.start()
    fails = []

    def check(label, ok, detail=""):
        if not ok:
            fails.append(label)
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {label}"
              + (f"  {D}{detail}{X}" if detail else ""))

    print(f"{B}Panels on their own ports{X}  {D}(panel.panltest -> 127.0.0.2){X}")
    res = engine.scan_control_panels("panel.panltest")
    found = {p["panel"]: p for p in res.get("panels", [])}
    print(f"  {D}open panel ports: {res.get('ports_open')}{X}")
    print(f"  {D}identified: {sorted(found)}{X}\n")

    for port, name in sorted(panellab.EXPECTED_PANELS.items()):
        got = found.get(name)
        check(f"{name:12} on port {port}", bool(got),
              f"signals={got['signals'][:2]}" if got else "not identified")

    print(f"\n{B}Evidence and detail{X}")
    check("Plesk version read from the login page",
          (found.get("Plesk") or {}).get("version") == "18.0.58",
          str((found.get("Plesk") or {}).get("version")))
    check("every panel carries its matched signals",
          all(p["signals"] for p in res["panels"]))
    check("every finding is marked confirmed",
          all(f.get("confidence") == "confirmed" for f in res["findings"]))
    check("findings explain the risk, not just the name",
          all("restrict it by IP" in f["detail"] for f in res["findings"]))

    print(f"\n{B}A port that answers but is not a panel{X}")
    check("port 2031 serving plain nginx is not called a panel",
          2031 not in {p["port"] for p in res["panels"]})
    check("it is reported as an unexplained open port instead",
          2031 in res.get("unexplained_ports", []),
          str(res.get("unexplained_ports")))
    check("non-panel port 8099 never probed",
          8099 not in res.get("ports_open", []))

    print(f"\n{B}The hosting company decoy{X}  "
          f"{D}(its site sells cPanel, WHM, Plesk and Webmin){X}")
    hosting = engine.scan_control_panels("hosting.panltest")
    hp = {p["panel"] for p in hosting.get("panels", [])}
    check("no panel reported from marketing prose", not hp,
          f"reported={sorted(hp)}" if hp else "none")
    check("no findings raised on the hosting site",
          not hosting.get("findings"))

    plain = engine.scan_control_panels("plain.panltest")
    check("ordinary site reports no panel",
          not plain.get("panels"))

    print(f"\n{B}CDN guard{X}  {D}(Cloudflare proxies 2082-2096 and 8443){X}")
    real_cdn = engine._cdn_identity
    engine._cdn_identity = lambda ip, domain=None: "cloudflare"
    try:
        cdn_res = engine.scan_control_panels("panel.panltest")
    finally:
        engine._cdn_identity = real_cdn
    skipped = engine._CDN_PROXIED_PANEL_PORTS
    check("CDN-proxied ports are excluded from probing",
          not (set(cdn_res.get("ports_open", [])) & skipped),
          f"open={cdn_res.get('ports_open')}")
    check("cPanel on 2083 not claimed behind a CDN",
          "cPanel" not in {p["panel"] for p in cdn_res.get("panels", [])})
    check("the exclusion is explained in the output",
          bool(cdn_res.get("cdn_note")) and "edge" in cdn_res["cdn_note"])
    check("non-proxied panel ports still checked behind a CDN",
          10000 in cdn_res.get("ports_open", []),
          f"open={cdn_res.get('ports_open')}")

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for f in fails:
            print("  -", f)
        return 1
    print(f"{G}panels identified by their login interface, not their name — a "
          f"hosting company's own site reports none{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
