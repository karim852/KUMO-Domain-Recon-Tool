"""
CMS module tests: does it identify the right CMS, and does it stay quiet
when there is no CMS at all?

The second question is the one that matters. A scanner that decides a site runs
WordPress because the word "WordPress" appears in the page will then probe
dozens of WordPress paths that cannot exist, and report whatever the catch-all
returns. So the lab includes a blog that writes *about* WordPress, Joomla and
Drupal without running any of them, and the module must report no CMS for it.

    python3 test_cms.py
"""
import os
import warnings

warnings.filterwarnings("ignore")

os.environ["NO_PROXY"] = (os.environ.get("NO_PROXY", "") + ",.cmstest,"
                          "wp.cmstest,joomla.cmstest,drupal.cmstest,"
                          "blog.cmstest,plain.cmstest")
os.environ["no_proxy"] = os.environ["NO_PROXY"]

import cmslab
import engine

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"


def main():
    cmslab.start()
    fails = []

    def check(label, ok, detail=""):
        if not ok:
            fails.append(label)
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {label}"
              + (f"  {D}{detail}{X}" if detail else ""))

    print(f"{B}CMS identification{X}")
    results = {}
    for host, expected in cmslab.EXPECTED_CMS.items():
        res = engine.scan_cms(host)
        results[host] = res
        got = res.get("cms")
        ok = got == expected
        check(f"{host:18} -> {got or 'none'}",
              ok, f"expected {expected or 'none'}, score={res.get('detection_score')}")

    print(f"\n{B}The decoys must stay silent{X}  "
          f"{D}(a site writing ABOUT a CMS does not run it){X}")
    blog = results["blog.cmstest"]
    plain = results["plain.cmstest"]
    check("blog that discusses all three CMSes identifies none",
          blog.get("cms") is None, f"candidates={blog.get('candidates')}")
    check("blog produced no findings", not blog.get("findings"))
    check("blog probed no CMS paths", blog.get("paths_probed", 0) == 0)
    check("plain site identifies no CMS", plain.get("cms") is None)
    check("plain site produced no findings", not plain.get("findings"))

    print(f"\n{B}WordPress{X}")
    wp = results["wp.cmstest"]
    names = [f["name"] for f in wp.get("findings", [])]
    check("version read from the generator meta",
          wp.get("version") == "6.4.2", str(wp.get("version")))
    check("wp-config backup found",
          any("wp-config backup" in n for n in names))
    check("debug log found", any("debug log" in n for n in names))
    check("installer found reachable", any("installer" in n for n in names))
    users = [u["slug"] for u in wp.get("users", [])]
    check("users enumerated via REST API",
          {"hannah", "admin", "marc"} <= set(users), str(users))
    check("user enumeration reported as a finding",
          any("user enumeration" in n.lower() for n in names))
    plugins = {p["name"]: p["version"] for p in wp.get("plugins", [])}
    check("plugins read from the homepage",
          {"woocommerce", "contact-form-7"} <= set(plugins), str(list(plugins)))
    check("plugin versions read from their readme",
          plugins.get("woocommerce") == "8.4.0", str(plugins))
    themes = {t["name"]: t["version"] for t in wp.get("themes", [])}
    check("theme detected with version",
          themes.get("astra") == "4.6.0", str(themes))

    print(f"\n{B}Joomla{X}")
    jm = results["joomla.cmstest"]
    jnames = [f["name"] for f in jm.get("findings", [])]
    check("version read from the manifest",
          jm.get("version") == "4.2.7", str(jm.get("version")))
    check("configuration backup found",
          any("configuration backup" in n for n in jnames))
    check("installer still present reported",
          any("installer" in n for n in jnames))
    check("no WordPress path was probed on a Joomla site",
          not any("wp-" in (f.get("path") or "") for f in jm.get("findings", [])))

    print(f"\n{B}Drupal{X}")
    dr = results["drupal.cmstest"]
    dnames = [f["name"] for f in dr.get("findings", [])]
    check("version read from CHANGELOG",
          dr.get("version") == "9.5.11", str(dr.get("version")))
    check("settings.php backup found",
          any("settings.php backup" in n for n in dnames))
    check("installer found reachable", any("installer" in n for n in dnames))
    check("no WordPress path was probed on a Drupal site",
          not any("wp-" in (f.get("path") or "") for f in dr.get("findings", [])))

    print(f"\n{B}Platform fingerprinting{X}  "
          f"{D}(20 platforms recognised, 3 deep-scanned){X}")
    for host, cms in (("wp.cmstest", "WordPress"), ("joomla.cmstest", "Joomla"),
                      ("drupal.cmstest", "Drupal")):
        r = results[host]
        check(f"{cms:10} corroborated by the fingerprint table",
              r.get("corroborated_by") == "platform fingerprint",
              f"platforms={r.get('platforms')}")
    check("WooCommerce listed as an add-on, not a rival platform",
          results["wp.cmstest"].get("addons") == ["WooCommerce"]
          and not results["wp.cmstest"].get("not_deep_scanned"))

    mag = results["magento.cmstest"]
    check("Magento storefront is fingerprinted", mag.get("platforms") == ["Magento"])
    check("Magento is reported as having no deep checks",
          mag.get("not_deep_scanned") == ["Magento"])
    check("the result says so instead of coming back blank",
          "no deep checks" in (mag.get("note") or ""), mag.get("note"))
    check("no WordPress/Joomla/Drupal path probed on a Magento site",
          not mag.get("findings"))

    for host in ("blog.cmstest", "plain.cmstest"):
        check(f"{host:14} fingerprints no platform at all",
              not results[host].get("platforms"),
              str(results[host].get("platforms")))

    print(f"\n{B}No signature matches a bare product name{X}  "
          f"{D}(guards the whole fingerprint table, not just the labs){X}")
    # Every brand in the table, written the way its own marketing writes it.
    # This is the page a tech blog or a hosting reseller publishes. Nothing in
    # it is installed software, so nothing here may fingerprint.
    import re as _re
    # EVERY brand in the whole table, not just the CMS and storefront ones.
    # Checking only those twenty left nine prose matches in the other nine
    # categories -- Backbone.js, Tawk.to, Wordfence, Keycloak, GraphQL,
    # gRPC-Web, WebSocket, REST API and Netlify -- which the browser
    # extension's copy of this test is what actually caught.
    names = sorted({n for sigs in engine._WW_SIGNATURES.values() for n in sigs})
    prose = ("<html><head><title>Platform roundup</title></head><body>"
             "<h1>Every platform compared</h1><p>"
             + ". ".join(f"{n}! is worth a look, and {n} keeps improving"
                         for n in names)
             + ".</p><p>Debugging tip: check the <code>cf-ray</code>, "
               "<code>x-sucuri-id</code> and <code>X-Powered-By: Express</code> "
               "headers, and the <code>incap_ses</code> cookie.</p>"
               "<p>We also cover settings.php and configuration.php hardening.</p>"
               "</body></html>")
    def _scan_all(body, headers):
        """Run the FULL signature table the way _whatweb_python does."""
        hblob = str(headers)
        hay = body + hblob
        out = []
        for cat, sigs in engine._WW_SIGNATURES.items():
            for name, pats in sigs.items():
                for pat in pats:
                    if isinstance(pat, tuple):
                        target = hblob if pat[0] == "h" else body
                        src = pat[1]
                    else:
                        target, src = hay, pat
                    if _re.search(src, target, _re.I):
                        out.append(f"{cat}/{name}")
                        break
        return out

    leaked = _scan_all(prose, {})
    check(f"all {len(names)} brands named in prose fingerprint nothing",
          not leaked, f"leaked={leaked}" if leaked else "")

    # and the same text must not fingerprint when it arrives as headers either
    leaked_h = _scan_all("", {"X-Note": " ".join(names)})
    check("brand names in a header value fingerprint nothing",
          not leaked_h, f"leaked={leaked_h}" if leaked_h else "")

    # the scoped-away evidence must still work where it genuinely belongs
    check("Cloudflare detected from its own header",
          any("Cloudflare" in x for x in _scan_all("", {"cf-ray": "8a1b-CDG"})))
    check("Cloudflare NOT detected from the same words in the body",
          not any("Cloudflare" in x
                  for x in _scan_all("<p>we use cloudflare, see cf-ray</p>", {})))

    print(f"\n{B}Evidence discipline{X}")
    allf = [f for r in results.values() for f in r.get("findings", [])]
    check("every finding carries a confidence",
          all(f.get("confidence") for f in allf), f"{len(allf)} findings")
    check("version findings marked as inference, not proof",
          all(f.get("confidence") == "version-inference"
              for f in allf if "version disclosed" in f["name"]))
    check("config backups rated critical",
          all(f["severity"] == "critical" for f in allf
              if "backup" in f["name"] and "config" in f["name"].lower()))

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for f in fails:
            print("  -", f)
        return 1
    print(f"{G}each CMS identified and probed with only its own checks, and a "
          f"site that merely writes about a CMS is not reported as running it{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
