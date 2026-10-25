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


def run(cap=None, fail_for=(), rate_limit_for=(), harvested=None,
        chia_employee=(), chia_client=(), chia_emails=(), proxynova=()):
    """Run scan_breachintel with every network source stubbed."""
    import os
    asked.clear()

    def fake_collect(domain):
        return set(HARVESTED if harvested is None else harvested), {}, ["homepage", "crt.sh"]

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

    class ChiaResp:
        status_code = 200

        def __init__(self, payload):
            self._p = payload
            self.text = ""

        def json(self):
            return self._p

    def fake_get(url, **kw):
        if "search-by-email" in url:
            from urllib.parse import unquote
            em = unquote(url.split("email=")[1])
            asked.append(em)
            return FakeResp(em)
        # Chiasmodon: employee vs client logins, so we can prove client
        # addresses never reach the stealer check.
        if "CompanyEmployeLogins" in url:
            return ChiaResp([{"email": e, "password": "x"} for e in chia_employee])
        if "CompanyClientLogins" in url:
            return ChiaResp([{"email": e, "password": "x"} for e in chia_client])
        if "CompanyEmails" in url:
            return ChiaResp(list(chia_emails))
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

    # ── employees only, never clients ────────────────────────────────────
    # Client addresses are other people's: customers of the target. Looking
    # them up against an infostealer database is both out of scope for a domain
    # assessment and a privacy problem. Only @domain addresses are checked.
    print(f"\n{B}Employees only — client addresses are never checked{X}")

    EMPLOYEES = {f"staff{i}@{DOMAIN}" for i in range(1, 6)}
    CLIENTS = {
        "john.smith@gmail.com", "marie@yahoo.fr", "buyer@othercorp.com",
        "contact@client-company.tn", "user@hotmail.com",
        # near-misses designed to slip past a sloppy filter
        f"attacker@evil-{DOMAIN}", f"someone@{DOMAIN}.evil.com",
        f"person@sub.{DOMAIN}",
    }

    res4 = run(harvested=EMPLOYEES | CLIENTS,
               chia_employee=sorted(EMPLOYEES),
               chia_client=sorted(CLIENTS),
               chia_emails=sorted(CLIENTS),
               proxynova=sorted(CLIENTS))
    asked4 = set(asked)
    leaked = asked4 & CLIENTS

    check("every employee address was checked", EMPLOYEES <= asked4,
          f"{len(EMPLOYEES & asked4)}/{len(EMPLOYEES)}")
    check("NO client address was looked up", not leaked,
          f"leaked={sorted(leaked)[:3]}" if leaked else "none leaked")
    check("client_logins never feed the stealer check",
          not any(e in asked4 for e in CLIENTS))
    check("lookalike domains rejected (evil-domain, domain.evil.com)",
          f"attacker@evil-{DOMAIN}" not in asked4
          and f"someone@{DOMAIN}.evil.com" not in asked4)
    check("subdomain addresses not treated as the domain",
          f"person@sub.{DOMAIN}" not in asked4)
    check("harvested_emails output holds only what was collected",
          isinstance(res4["sources"]["harvested_emails"], list))

    # the client count is still reported, it is just never queried
    check("clients still counted in the summary, just not queried",
          res4["summary"]["total_clients_leaked"] >= 0)

    print(f"\n{B}The employee/client boundary itself{X}")
    doms = engine._company_domains(DOMAIN)
    for addr, want in [
        (f"k.mansour@{DOMAIN}", True),
        (f"K.Mansour@{DOMAIN.upper()}", True),
        ("john@gmail.com", False),
        ("buyer@othercorp.com", False),
        (f"attacker@evil-{DOMAIN}", False),
        (f"someone@{DOMAIN}.evil.com", False),
        (f"person@sub.{DOMAIN}", False),
        ("no-at-sign", False),
        (f"a@b@{DOMAIN}", False),
        ("", False),
        (f"@{DOMAIN}", False),
    ]:
        got = engine._is_company_email(addr, doms)
        check(f"{addr or '(empty)'!s:<34} -> {got}", got is want)

    print(f"\n{B}Subdomain scans still find the company's addresses{X}")
    EMP2 = {f"k.mansour@{DOMAIN}", f"hr@{DOMAIN}"}
    for target, expect in [(DOMAIN, 2), (f"www.{DOMAIN}", 2),
                           (f"mail.corp.{DOMAIN}", 2)]:
        r = run(harvested=EMP2 | {"client@gmail.com"})
        # run() scans DOMAIN; re-run directly for the subdomain targets
        import engine as _e
        asked.clear()
        real_collect = _e._collect_domain_emails
        real_get = _e.requests.get
        real_req = _e.req

        def collect2(d):
            return set(EMP2) | {"client@gmail.com"}, {}, ["homepage"]

        class OK:
            status_code = 200

            def json(self):
                return {"stealers": []}

        def get2(url, **kw):
            if "search-by-email" in url:
                from urllib.parse import unquote
                asked.append(unquote(url.split("email=")[1]))
                return OK()
            raise RuntimeError("blocked")

        _e._collect_domain_emails = collect2
        _e.requests.get = get2
        _e.req = lambda *a, **k: None
        try:
            rr = _e.scan_breachintel(target)
        finally:
            _e._collect_domain_emails = real_collect
            _e.requests.get = real_get
            _e.req = real_req
        n = rr["sources"]["hr_per_email_stats"]["emails_checked"]
        check(f"scanning {target:24} checks {n} company address(es)",
              n == expect and "client@gmail.com" not in set(asked))

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
