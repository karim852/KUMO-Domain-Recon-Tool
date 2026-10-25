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
