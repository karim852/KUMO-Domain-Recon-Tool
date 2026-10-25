"""
Per-email stealer check coverage (breachintel module).

The question this answers is "did every address we collected actually get
checked?". Three things used to make the answer no:

  1. The first per-email block built its address set in a loop whose body was a
     bare `pass`, so the set was always empty and the check never ran at all.
  2. The second block checked sorted(...)[:20] — on a domain with 60 addresses,
     40 went unchecked and nothing in the output said so.
  3. The harvester's addresses never reached the check: harvested_emails was
     hardcoded to [] with a comment saying another module would fill it, which
     nothing ever did. So the company's published staff addresses — the ones
     most worth checking — were the ones being skipped.

Hudson Rock is stubbed here; the point is which addresses get asked about.

    python3 test_stealer_coverage.py
"""
import warnings

warnings.filterwarnings("ignore")

import engine

G = "\033[92m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"

DOMAIN = "acme-corp.com"

# 60 harvested addresses: well past the old cap of 20, and deliberately spread
# across the alphabet so truncation is obvious.
HARVESTED = {f"{c}{i}.staff@{DOMAIN}"
             for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"[:20], 1)} | {
    f"user{i:02d}@{DOMAIN}" for i in range(1, 41)
}

asked = []


def run(cap=None, fail_for=(), rate_limit_for=()):
    """Run scan_breachintel with every network source stubbed."""
    import os
    asked.clear()

    def fake_collect(domain):
        return set(HARVESTED), {}, ["homepage", "crt.sh"]

    class FakeResp:
        def __init__(self, email):
            self.email = email
            if email in rate_limit_for:
                self.status_code = 429
            elif email in fail_for:
                self.status_code = 500
            else:
                self.status_code = 200

        def json(self):
            # every third address is "infected", the rest clean
            n = sum(ord(c) for c in self.email)
            if n % 3 == 0:
                return {"stealers": [{"date_compromised": "2026-09-18T00:00:00Z",
                                      "computer_name": "PC-" + self.email[:4],
                                      "operating_system": "Windows 11",
                                      "top_passwords": ["hunter2"]}],
                        "total_corporate_services": 3,
                        "total_user_services": 7}
            return {"stealers": []}

    def fake_get(url, **kw):
        if "search-by-email" in url:
            from urllib.parse import unquote
            em = unquote(url.split("email=")[1])
            asked.append(em)
            return FakeResp(em)
        raise RuntimeError("blocked: " + url[:60])

    real_collect = engine._collect_domain_emails
    real_get = engine.requests.get
    real_req = engine.req
    old_cap = os.environ.get("KUMO_MAX_EMAIL_CHECKS")
    if cap is None:
        os.environ.pop("KUMO_MAX_EMAIL_CHECKS", None)
    else:
        os.environ["KUMO_MAX_EMAIL_CHECKS"] = str(cap)

    engine._collect_domain_emails = fake_collect
    engine.requests.get = fake_get
    engine.req = lambda *a, **k: None          # kill HIBP / crt.sh / hunter
    try:
        return engine.scan_breachintel(DOMAIN)
    finally:
        engine._collect_domain_emails = real_collect
        engine.requests.get = real_get
        engine.req = real_req
        if old_cap is None:
            os.environ.pop("KUMO_MAX_EMAIL_CHECKS", None)
        else:
            os.environ["KUMO_MAX_EMAIL_CHECKS"] = old_cap


def main():
    fails = []

    def check(label, ok, detail=""):
        fails.append(label) if not ok else None
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {label}"
              + (f"  {D}{detail}{X}" if detail else ""))

    print(f"{B}Every harvested address is checked{X}  "
          f"{D}({len(HARVESTED)} addresses, old cap was 20){X}")
    res = run()
    stats = res["sources"]["hr_per_email_stats"]
    per = res["sources"]["hr_per_email"]

    check("every harvested address was asked about",
          set(asked) == HARVESTED,
          f"asked {len(set(asked))} of {len(HARVESTED)}")
    check("no address silently dropped", stats["emails_skipped"] == 0,
          f"skipped={stats['emails_skipped']}")
    check("stats report the full collection",
          stats["emails_collected"] == len(HARVESTED),
          f"collected={stats['emails_collected']}")
    check("every checked address has a result",
          len(per) == len(HARVESTED), f"results={len(per)}")
    check("harvester addresses are surfaced in the output",
          len(res["sources"]["harvested_emails"]) == len(HARVESTED))
    check("harvester counted as a source",
          stats["sources"]["harvester"] == len(HARVESTED))
    check("compromised + clean + unknown accounts for all",
          stats["compromised"] + stats["clean"] + stats["unknown"] == len(per),
          f"{stats['compromised']}/{stats['clean']}/{stats['unknown']}")
    check("some addresses came back infected", stats["compromised"] > 0,
          f"infected={stats['compromised']}")

    print(f"\n{B}A failed lookup is not 'clean'{X}")
    rl = sorted(HARVESTED)[:5]
    er = sorted(HARVESTED)[5:8]
    res2 = run(rate_limit_for=set(rl), fail_for=set(er))
    s2 = res2["sources"]["hr_per_email_stats"]
    p2 = res2["sources"]["hr_per_email"]
    check("rate-limited addresses reported as unknown, not clean",
          all(p2[e]["compromised"] is None for e in rl),
          f"statuses={[p2[e].get('status') for e in rl[:2]]}")
    check("HTTP error addresses reported as unknown",
          all(p2[e]["compromised"] is None for e in er))
    check("unknown counted separately from clean",
          s2["unknown"] >= len(rl) + len(er), f"unknown={s2['unknown']}")
    check("no unknown address was counted clean",
          s2["clean"] == sum(1 for v in p2.values() if v.get("compromised") is False))

    print(f"\n{B}The cap is opt-in and always reported{X}")
    res3 = run(cap=10)
    s3 = res3["sources"]["hr_per_email_stats"]
    check("cap limits the checks", s3["emails_checked"] == 10,
          f"checked={s3['emails_checked']}")
    check("skipped count is surfaced, not silent",
          s3["emails_skipped"] == len(HARVESTED) - 10,
          f"skipped={s3['emails_skipped']}")
    check("collection total still reported in full",
          s3["emails_collected"] == len(HARVESTED))

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for f in fails:
            print("  -", f)
        return 1
    print(f"{G}every collected address is checked, nothing is dropped silently, "
          f"and a failed lookup is never reported as clean{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
